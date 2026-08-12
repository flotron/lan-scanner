#include <jni.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <cerrno>

extern "C" JNIEXPORT jstring JNICALL
Java_com_flotron_lanscanner_NativeArp_lookupNative(
        JNIEnv *env, jobject, jstring ip_value, jstring interface_value) {
    const char *ip = env->GetStringUTFChars(ip_value, nullptr);
    const char *interface_name = env->GetStringUTFChars(interface_value, nullptr);

    int socket_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    arpreq request{};
    auto *address = reinterpret_cast<sockaddr_in *>(&request.arp_pa);
    address->sin_family = AF_INET;
    const bool valid_ip = inet_pton(AF_INET, ip, &address->sin_addr) == 1;
    std::strncpy(request.arp_dev, interface_name, IFNAMSIZ - 1);

    const bool found = socket_fd >= 0 && valid_ip &&
                       ioctl(socket_fd, SIOCGARP, &request) == 0 &&
                       (request.arp_flags & ATF_COM) != 0;
    if (socket_fd >= 0) close(socket_fd);
    env->ReleaseStringUTFChars(ip_value, ip);
    env->ReleaseStringUTFChars(interface_value, interface_name);
    if (!found) return nullptr;

    const auto *mac = reinterpret_cast<unsigned char *>(request.arp_ha.sa_data);
    char formatted[18];
    std::snprintf(formatted, sizeof(formatted), "%02X:%02X:%02X:%02X:%02X:%02X",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    if (std::strcmp(formatted, "00:00:00:00:00:00") == 0) return nullptr;
    return env->NewStringUTF(formatted);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_flotron_lanscanner_NativeArp_dumpNative(
        JNIEnv *env, jobject, jstring interface_value) {
    const char *interface_name = env->GetStringUTFChars(interface_value, nullptr);
    const unsigned int interface_index = if_nametoindex(interface_name);
    env->ReleaseStringUTFChars(interface_value, interface_name);
    if (interface_index == 0) return env->NewStringUTF("!INTERFACE NOT FOUND");

    const int socket_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (socket_fd < 0) {
        char error[64]; std::snprintf(error, sizeof(error), "!NETLINK SOCKET ERROR %d", errno);
        return env->NewStringUTF(error);
    }

    struct {
        nlmsghdr header;
        ndmsg neighbor;
    } request{};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(ndmsg));
    request.header.nlmsg_type = RTM_GETNEIGH;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = 1;
    request.neighbor.ndm_family = AF_INET;
    request.neighbor.ndm_ifindex = static_cast<int>(interface_index);

    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    if (sendto(socket_fd, &request, request.header.nlmsg_len, 0,
               reinterpret_cast<sockaddr *>(&kernel), sizeof(kernel)) < 0) {
        const int error_number = errno;
        close(socket_fd);
        char error[64]; std::snprintf(error, sizeof(error), "!NETLINK SEND ERROR %d", error_number);
        return env->NewStringUTF(error);
    }

    std::string result;
    bool complete = false;
    while (!complete) {
        char buffer[16384];
        const ssize_t received = recv(socket_fd, buffer, sizeof(buffer), 0);
        if (received < 0) {
            char error[64]; std::snprintf(error, sizeof(error), "!NETLINK RECEIVE ERROR %d", errno);
            close(socket_fd); return env->NewStringUTF(error);
        }
        if (received == 0) break;
        int remaining = static_cast<int>(received);
        for (nlmsghdr *header = reinterpret_cast<nlmsghdr *>(buffer);
             NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining)) {
            if (header->nlmsg_type == NLMSG_DONE) { complete = true; break; }
            if (header->nlmsg_type == NLMSG_ERROR) { complete = true; break; }
            if (header->nlmsg_type != RTM_NEWNEIGH) continue;

            auto *neighbor = reinterpret_cast<ndmsg *>(NLMSG_DATA(header));
            if (neighbor->ndm_family != AF_INET ||
                neighbor->ndm_ifindex != static_cast<int>(interface_index) ||
                (neighbor->ndm_state & (NUD_INCOMPLETE | NUD_FAILED)) != 0) continue;

            char ip[INET_ADDRSTRLEN]{};
            unsigned char mac[6]{};
            bool has_ip = false, has_mac = false;
            int attributes_length = static_cast<int>(header->nlmsg_len) - NLMSG_LENGTH(sizeof(ndmsg));
            for (rtattr *attribute = reinterpret_cast<rtattr *>(
                     reinterpret_cast<char *>(neighbor) + NLMSG_ALIGN(sizeof(ndmsg)));
                 RTA_OK(attribute, attributes_length);
                 attribute = RTA_NEXT(attribute, attributes_length)) {
                if (attribute->rta_type == NDA_DST && RTA_PAYLOAD(attribute) >= 4) {
                    has_ip = inet_ntop(AF_INET, RTA_DATA(attribute), ip, sizeof(ip)) != nullptr;
                } else if (attribute->rta_type == NDA_LLADDR && RTA_PAYLOAD(attribute) >= 6) {
                    std::memcpy(mac, RTA_DATA(attribute), 6); has_mac = true;
                }
            }
            if (!has_ip || !has_mac) continue;
            char formatted[18];
            std::snprintf(formatted, sizeof(formatted), "%02X:%02X:%02X:%02X:%02X:%02X",
                          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            if (std::strcmp(formatted, "00:00:00:00:00:00") != 0) {
                result.append(ip).append("=").append(formatted).append("\n");
            }
        }
    }
    close(socket_fd);
    if (result.empty()) return env->NewStringUTF("!NETLINK RETURNED NO ARP NEIGHBORS");
    return env->NewStringUTF(result.c_str());
}
