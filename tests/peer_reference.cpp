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
	const auto port = 33333;
	if(ec) throw std::runtime_error("tcp error code");
	c_peer_reference_tcp peer_reference_tcp(ip, port);
	EXPECT_EQ(peer_reference_tcp.get_type(), c_peer_reference::type::e_tcp);
	EXPECT_EQ(peer_reference_tcp.to_string(), "192.168.122.2:33333");
	const auto endpoint = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("192.168.122.2"), 33333);
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
	const auto endpoint = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("192.168.122.2"), 33333);
	c_peer_reference_tcp peer_reference_tcp(endpoint);
	EXPECT_EQ(peer_reference_tcp.get_type(), c_peer_reference::type::e_tcp);
	EXPECT_EQ(peer_reference_tcp.get_endpoint(), endpoint);
	const auto peer_reference_clone = dynamic_cast<c_peer_reference_tcp&>(*peer_reference_tcp.clone());
	EXPECT_EQ(peer_reference_clone, peer_reference_tcp);
	EXPECT_EQ(peer_reference_tcp.to_string(), "192.168.122.2:33333");
}

TEST(peer_reference, url){
	c_peer_reference_url peer_reference_url;
	EXPECT_EQ(peer_reference_url.get_type(), c_peer_reference::type::e_url);
}

TEST(peer_reference, url_with_endpoint){
	boost::asio::io_context io_context;
	boost::asio::ip::tcp::resolver resolver(io_context);
	boost::asio::ip::tcp::resolver::query query("ivoting.pl", "33333");
	boost::asio::ip::tcp::resolver::iterator it = resolver.resolve(query);
	c_peer_reference_url peer_reference_url(it->endpoint());
	EXPECT_EQ(peer_reference_url.get_type(), c_peer_reference::type::e_url);
	EXPECT_EQ(peer_reference_url.get_endpoint(), it->endpoint());
	const auto peer_reference_clone = dynamic_cast<c_peer_reference_url&>(*peer_reference_url.clone());
	EXPECT_EQ(peer_reference_clone, peer_reference_url);
	c_peer_reference_url_creator url_peer_creator;
	const auto new_peer_reference = url_peer_creator.create_peer_reference("ivoting.pl", 33333);
	const auto new_peer_reference_url = dynamic_cast<c_peer_reference_url&>(*new_peer_reference);
	EXPECT_EQ(new_peer_reference_url.get_endpoint(), it->endpoint());
	const auto new_peer_ref_from_free_function = create_peer_reference("ivoting.pl", 33333);
	const auto new_peer_reference_url_from_free_function = dynamic_cast<c_peer_reference_url&>(*new_peer_ref_from_free_function);
	EXPECT_EQ(new_peer_reference_url_from_free_function.get_endpoint(), it->endpoint());
}
