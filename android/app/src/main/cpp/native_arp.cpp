#include <jni.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>

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
