#include "port_forwarder.hpp"
#include "logger.hpp"
#include <miniupnpc.h>
#include <upnpcommands.h>
#include <upnperrors.h>
#include <stdexcept>

#ifdef NATPMP
#include <natpmp.h>
#endif

#if defined(_MSC_VER)
#if _MSC_VER >= 1400
#define strcasecmp _stricmp
#else
#define strcasecmp stricmp
#endif
#else
#include <unistd.h>
#endif
#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

c_port_forwarder::c_port_forwarder(t_broadcast_ip_callback broadcast_ip_callback)
	:
	  m_broadcast_callback(broadcast_ip_callback),
	  m_port(),
	  m_stop_flag(false),
	  m_main_loop_thread()
{
}

void c_port_forwarder::start(const unsigned short port) {
	m_port = port;
	m_main_loop_thread = std::thread(&c_port_forwarder::main_loop, this);
}


c_port_forwarder::~c_port_forwarder() {
	stop();
	if (m_main_loop_thread.joinable()) m_main_loop_thread.join();
}

void c_port_forwarder::stop() {
	m_stop_flag = true;
	m_sleeper_reannounce.wake_up();
	m_sleeper_retry.wake_up();
}

std::optional<std::pair<std::string, unsigned short>> c_port_forwarder::get_my_public_ip() const {
	std::shared_lock<std::shared_mutex> lock(m_my_public_address_mutex);
	return m_my_public_address;
}

bool c_port_forwarder::forward_port_upnp() {
	const char * multicastif = nullptr;
	const char * minissdpdpath = nullptr;
	int error = 0;
	UPNPDev * devlist = nullptr;
	devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0, 0, 2, &error);
	if (error != UPNPDISCOVER_SUCCESS) return false;
	
	struct UPNPUrls urls;
	const auto deleter = [&urls, &devlist](bool free_urls){
		freeUPNPDevlist(devlist);
		devlist = nullptr;
		if (free_urls)
			FreeUPNPUrls(&urls);
	};
	
	struct IGDdatas data;
	int r;
	char lanaddr[64];
	r = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));
	if (r == -1) { // Internal error
		deleter(false);
		return false;
	} else if (r == 0) { // NO IGD found
		deleter(false);
		return false;
	} else if (r == 1) { // A valid connected IGD has been found
		char externalIPAddress[40];
		r = UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, externalIPAddress);
		if (r != 0) {
			deleter(true);
			return false;
		}
		std::lock_guard<std::shared_mutex> lock(m_my_public_address_mutex);
		m_my_public_address = std::make_pair(externalIPAddress, m_port);
		m_broadcast_callback(m_my_public_address->first, m_my_public_address->second);
	}
	const auto port_as_string = std::to_string(m_port);
	bool return_value = false;
	while (!m_stop_flag) {
		r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype, port_as_string.c_str(), port_as_string.c_str(), lanaddr, "iVoting node", "TCP", nullptr, "0");
		if (r != UPNPCOMMAND_SUCCESS) {
			return_value = false;
			break;
		}
		else return_value = true;
		m_sleeper_reannounce.sleep_for(m_port_mapping_reannounce_period);
	}
	
	UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, port_as_string.c_str(), "TCP", nullptr);
	deleter(true);
	return return_value;
}

/* List of IP address blocks which are private / reserved and therefore not suitable for public external IP addresses */
#define IP(a, b, c, d) ((static_cast<uint32_t>(a) << 24) + ((b) << 16) + ((c) << 8) + (d))
#define MSK(m) (32-(m))
static const struct { uint32_t address; uint32_t rmask; } reserved[] = {
	{ IP(  0,   0,   0, 0), MSK( 8) }, /* RFC1122 "This host on this network" */
	{ IP( 10,   0,   0, 0), MSK( 8) }, /* RFC1918 Private-Use */
	{ IP(100,  64,   0, 0), MSK(10) }, /* RFC6598 Shared Address Space */
	{ IP(127,   0,   0, 0), MSK( 8) }, /* RFC1122 Loopback */
	{ IP(169, 254,   0, 0), MSK(16) }, /* RFC3927 Link-Local */
	{ IP(172,  16,   0, 0), MSK(12) }, /* RFC1918 Private-Use */
	{ IP(192,   0,   0, 0), MSK(24) }, /* RFC6890 IETF Protocol Assignments */
	{ IP(192,   0,   2, 0), MSK(24) }, /* RFC5737 Documentation (TEST-NET-1) */
	{ IP(192,  31, 196, 0), MSK(24) }, /* RFC7535 AS112-v4 */
	{ IP(192,  52, 193, 0), MSK(24) }, /* RFC7450 AMT */
	{ IP(192,  88,  99, 0), MSK(24) }, /* RFC7526 6to4 Relay Anycast */
	{ IP(192, 168,   0, 0), MSK(16) }, /* RFC1918 Private-Use */
	{ IP(192, 175,  48, 0), MSK(24) }, /* RFC7534 Direct Delegation AS112 Service */
	{ IP(198,  18,   0, 0), MSK(15) }, /* RFC2544 Benchmarking */
	{ IP(198,  51, 100, 0), MSK(24) }, /* RFC5737 Documentation (TEST-NET-2) */
	{ IP(203,   0, 113, 0), MSK(24) }, /* RFC5737 Documentation (TEST-NET-3) */
	{ IP(224,   0,   0, 0), MSK( 4) }, /* RFC1112 Multicast */
	{ IP(240,   0,   0, 0), MSK( 4) }, /* RFC1112 Reserved for Future Use + RFC919 Limited Broadcast */
};
#undef IP
#undef MSK

bool c_port_forwarder::addr_is_reserved(struct in_addr * addr) const noexcept {
	uint32_t address = ntohl(addr->s_addr);
	size_t i;

	for (i = 0; i < sizeof(reserved)/sizeof(reserved[0]); ++i) {
		if ((address >> reserved[i].rmask) == (reserved[i].address >> reserved[i].rmask))
			return true;
	}
	return false;
}

#ifdef NATPMP
bool c_port_forwarder::forward_port_natpmp() {
	//bool return_value = false;
	int ret = 0;
	natpmp_t natpmp;
	natpmpresp_t response;
	in_addr_t forcedgw;
	ret = initnatpmp(&natpmp, 0, forcedgw);
	if (ret != 0) return false;
	ret = sendpublicaddressrequest(&natpmp);
	if (ret < 0) return false;
	timeval timeout;
	fd_set fds;
	do {
		FD_ZERO(&fds);
		FD_SET(natpmp.s, &fds);
		getnatpmprequesttimeout(&natpmp, &timeout);
		ret = select(FD_SETSIZE, &fds, nullptr, nullptr, &timeout);
		if(ret < 0) {
			LOG(error) << "select() error";
			return false;
		}
		ret = readnatpmpresponseorretry(&natpmp, &response);
		if((ret < 0) && (ret != NATPMP_TRYAGAIN)) {
			LOG(error) << "readnatpmpresponseorretry() failed : \n" << ret;
		}
	} while((ret == NATPMP_TRYAGAIN) && (!m_stop_flag));
	if(ret < 0) return false;

	if(response.type != NATPMP_RESPTYPE_PUBLICADDRESS) {
		LOG(error) << "readnatpmpresponseorretry() failed : invalid response type " << response.type;
		return false;
	}

	if(addr_is_reserved(&response.pnu.publicaddress.addr)) {
		LOG(error) << "readnatpmpresponseorretry() failed : invalid Public IP address " << inet_ntoa(response.pnu.publicaddress.addr);
		return false;
	}
	
	{
		std::lock_guard<std::shared_mutex> lock(m_my_public_address_mutex);
		m_my_public_address = std::make_pair(inet_ntoa(response.pnu.publicaddress.addr), m_port);
		m_broadcast_callback(m_my_public_address->first, m_my_public_address->second);
	}
	
	ret = sendnewportmappingrequest(&natpmp, NATPMP_PROTOCOL_TCP,
									  m_port, m_port,
									  5);
	if (ret != 12) return false;
	do {
		FD_ZERO(&fds);
		FD_SET(natpmp.s, &fds);
		getnatpmprequesttimeout(&natpmp, &timeout);
		select(FD_SETSIZE, &fds, nullptr, nullptr, &timeout);
		ret = readnatpmpresponseorretry(&natpmp, &response);
		m_sleeper_reannounce.sleep_for(m_port_mapping_reannounce_period);
	} while(ret == NATPMP_TRYAGAIN);
	
	closenatpmp(&natpmp);
	return ret;
}
#endif

void c_port_forwarder::main_loop() {
	while(!m_stop_flag) {
		#ifdef NATPMP
		if (!forward_port_upnp()) forward_port_natpmp();
		#endif
		m_sleeper_retry.sleep_for(m_port_mapping_retry_period);
	}
}
