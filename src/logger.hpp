#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <boost/log/trivial.hpp>

#if defined (IVOTING_TESTS) || defined (COVERAGE_TESTS)
	using boost::log::trivial::severity_level::trace;
	using boost::log::trivial::severity_level::debug;
	using boost::log::trivial::severity_level::info;
	using boost::log::trivial::severity_level::warning;
	using boost::log::trivial::severity_level::error;
	using boost::log::trivial::severity_level::fatal;
	
	class c_null_logger {
		public:
			template <typename T> c_null_logger(T) {}
			template <typename Val> c_null_logger& operator<< (const Val&) { return * this;}
	};
	#define LOG(lvl) c_null_logger(lvl)
#else

	#define LOG(log_) BOOST_LOG_TRIVIAL(log_) \
		<<  __FILE__ << ":" << __LINE__ << " "
#endif // IVOTING_TESTS || COVERAGE_TESTS
	
#endif // LOGGER_HPP
