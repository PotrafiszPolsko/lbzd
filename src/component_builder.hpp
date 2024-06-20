#ifndef COMPONENT_BUILDER_HPP
#define COMPONENT_BUILDER_HPP

#include <boost/program_options/variables_map.hpp>

class c_component_builder {
	public:
		virtual ~c_component_builder() = default;
		virtual void set_program_options(const boost::program_options::variables_map & vm) = 0;
};

#endif // COMPONENT_BUILDER_HPP
