#include <gtest/gtest.h>
#include "../src/peer_reference.hpp"

TEST(peer_reference, tcp){
	c_peer_reference_tcp peer_reference_tcp;
	EXPECT_EQ(peer_reference_tcp.get_type(), c_peer_reference::type::e_tcp);
}

TEST(peer_reference, tcp_with_addres){
	boost::system::error_code ec;
	const auto address_str = "192.168.122.2";
	const auto ip = boost::asio::ip::make_address(address_str, ec);
	const auto port = 22086;
	if(ec) throw std::runtime_error("tcp error code");
	c_peer_reference_tcp peer_reference_tcp(ip, port);
	EXPECT_EQ(peer_reference_tcp.get_type(), c_peer_reference::type::e_tcp);
	EXPECT_EQ(peer_reference_tcp.to_string(), "192.168.122.2:22086");
	const auto endpoint = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("192.168.122.2"), 22086);
	EXPECT_EQ(peer_reference_tcp.get_endpoint(), endpoint);
	c_peer_reference_tcp_creator tcp_peer_creator;
	const auto new_peer_reference = tcp_peer_creator.create_peer_reference(address_str, port);
	const auto new_peer_reference_tcp = dynamic_cast<c_peer_reference_tcp&>(*new_peer_reference);
	EXPECT_EQ(new_peer_reference_tcp.get_endpoint(), endpoint);
	const auto new_peer_ref_from_free_function = create_peer_reference(address_str, port);
	const auto new_peer_reference_tcp_from_free_function = dynamic_cast<c_peer_reference_tcp&>(*new_peer_ref_from_free_function);
	EXPECT_EQ(new_peer_reference_tcp_from_free_function.get_endpoint(), endpoint);
}

TEST(peer_reference, tcp_with_endpoint){
	const auto endpoint = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("192.168.122.2"), 22086);
	c_peer_reference_tcp peer_reference_tcp(endpoint);
	EXPECT_EQ(peer_reference_tcp.get_type(), c_peer_reference::type::e_tcp);
	EXPECT_EQ(peer_reference_tcp.get_endpoint(), endpoint);
	const auto peer_reference_clone = dynamic_cast<c_peer_reference_tcp&>(*peer_reference_tcp.clone());
	EXPECT_EQ(peer_reference_clone, peer_reference_tcp);
	EXPECT_EQ(peer_reference_tcp.to_string(), "192.168.122.2:22086");
}

TEST(peer_reference, url){
	c_peer_reference_url peer_reference_url;
	EXPECT_EQ(peer_reference_url.get_type(), c_peer_reference::type::e_url);
}

TEST(peer_reference, url_with_endpoint){
	boost::asio::io_context io_context;
	boost::asio::ip::tcp::resolver resolver(io_context);
	boost::asio::ip::tcp::resolver::query query("ivoting.pl", "22086");
	boost::asio::ip::tcp::resolver::iterator it = resolver.resolve(query);
	c_peer_reference_url peer_reference_url(it->endpoint());
	EXPECT_EQ(peer_reference_url.get_type(), c_peer_reference::type::e_url);
	EXPECT_EQ(peer_reference_url.get_endpoint(), it->endpoint());
	const auto peer_reference_clone = dynamic_cast<c_peer_reference_url&>(*peer_reference_url.clone());
	EXPECT_EQ(peer_reference_clone, peer_reference_url);
	c_peer_reference_url_creator url_peer_creator;
	const auto new_peer_reference = url_peer_creator.create_peer_reference("ivoting.pl", 22086);
	const auto new_peer_reference_url = dynamic_cast<c_peer_reference_url&>(*new_peer_reference);
	EXPECT_EQ(new_peer_reference_url.get_endpoint(), it->endpoint());
	const auto new_peer_ref_from_free_function = create_peer_reference("ivoting.pl", 22086);
	const auto new_peer_reference_url_from_free_function = dynamic_cast<c_peer_reference_url&>(*new_peer_ref_from_free_function);
	EXPECT_EQ(new_peer_reference_url_from_free_function.get_endpoint(), it->endpoint());
}

TEST(peer_reference, onion){
	c_peer_reference_onion peer_reference_onion;
	EXPECT_EQ(peer_reference_onion.get_type(), c_peer_reference::type::e_onion);
}

TEST(peer_reference, onion_with_endpoint){
	const auto address_str = "jzn4p5ujyz74gqjpexxs7fidlsqmqqm4uefrj24ei35mwf4jlaajzja.onion";
	const auto port = 22086;
	c_peer_reference_onion peer_reference_onion(address_str, port);
	EXPECT_EQ(peer_reference_onion.get_type(), c_peer_reference::type::e_onion);
	const auto peer_reference_clone = dynamic_cast<c_peer_reference_onion&>(*peer_reference_onion.clone());
	EXPECT_EQ(peer_reference_clone, peer_reference_onion);
	EXPECT_EQ(peer_reference_onion.to_string(), "jzn4p5ujyz74gqjpexxs7fidlsqmqqm4uefrj24ei35mwf4jlaajzja.onion:22086");
	EXPECT_EQ(peer_reference_onion.get_onion_address(), "jzn4p5ujyz74gqjpexxs7fidlsqmqqm4uefrj24ei35mwf4jlaajzja.onion");
	EXPECT_EQ(peer_reference_onion.get_port(), 22086);
	EXPECT_EQ(peer_reference_onion.is_hidden_remote(), false);
	EXPECT_EQ(peer_reference_onion.get_socks5_credentials().m_password_soks5.size(), 0xff);
	EXPECT_EQ(peer_reference_onion.get_socks5_credentials().m_username_soks5.size(), 0xff);
	c_peer_reference_onion_creator onion_peer_creator;
	const auto new_peer_reference = onion_peer_creator.create_peer_reference(address_str, port);
	const auto new_peer_reference_onion = dynamic_cast<c_peer_reference_onion&>(*new_peer_reference);
	EXPECT_EQ(new_peer_reference_onion.get_onion_address(), "jzn4p5ujyz74gqjpexxs7fidlsqmqqm4uefrj24ei35mwf4jlaajzja.onion");
	EXPECT_EQ(new_peer_reference_onion.get_port(), 22086);
	const auto new_peer_ref_from_free_function = create_peer_reference(address_str, port);
	const auto new_peer_reference_onion_from_free_function = dynamic_cast<c_peer_reference_onion&>(*new_peer_ref_from_free_function);
	EXPECT_EQ(new_peer_reference_onion_from_free_function.get_onion_address(), "jzn4p5ujyz74gqjpexxs7fidlsqmqqm4uefrj24ei35mwf4jlaajzja.onion");
	EXPECT_EQ(new_peer_reference_onion_from_free_function.get_port(), 22086);
}

