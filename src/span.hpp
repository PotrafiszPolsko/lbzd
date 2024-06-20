#ifndef included_PFP_SPAN_HPP
#define included_PFP_SPAN_HPP

/***
 * @owner rob
 */

#include <type_traits>
#include <array>
#include <functional>
#include <iostream>
#include <limits>
#include <iterator>

constexpr auto dynamic_extent = std::numeric_limits<std::size_t>::max();

template<class T , std::size_t N = dynamic_extent>
class span;


/**
 * Converts span of any type - into span of constant bytes by doing a reinterpret of the data.
 * @note this function name is compatible with C++20
 */
template<class T , std::size_t N>
span<const unsigned char, N == dynamic_extent ? dynamic_extent : sizeof(T) * N> as_bytes(span<T, N> s) noexcept {
	return { reinterpret_cast< const unsigned char* >(s.data()), s.size() };
}

/**
 * Converts span of any type - into span of (non-constant) bytes. Of course the input span<T> must be of non-constant elements (eg not span<const ....>)
 * @note this function name is compatible with C++20
 */
template<class T , std::size_t N>
span< unsigned char, N == dynamic_extent ? dynamic_extent : sizeof(T) * N> as_writable_bytes(span<T, N> s) noexcept {
	static_assert(!(std::is_const<T>::value), "Do not cast away qualifiers (const)!"); // nicer error message
	return { reinterpret_cast< unsigned char* >(s.data()), s.size() };
}

/**
 * Implements a span (aiming to be compatible with C++20 std::span), that is a non-owning semi-container that refernces continous memory of N elements of type T.
 * The size N might be given in compile-time, or it can be given in runtime (in such case the template parameter Extent has special value, see elsewhere).
 *
 * Use-case:
 * 1. create it once
 * (you can NOT change it / re-seat it to reference other data / change its size or anything).
 * 2. use it: read the data - read the size, address, and access elements (possibly to write them, in case if T is non-const type).
 *
 * @warning [observer_container] - it does not own data; the data it observes must live longer and must not reallocate in memory
 */
template<class T , std::size_t Extent>
class span {

	public:
		using element_type = T;
		using value_type =  std::remove_cv_t<T>;
		using index_type = std::size_t;
		using difference_type = std::ptrdiff_t;
		using pointer = T*;
		using const_pointer = const T*;
		using reference = T&;

		span() = default;

		constexpr span(pointer ptr, index_type count);
		constexpr span(pointer first, pointer last);

		template <std::size_t N>
		constexpr span(element_type (&arr)[N]) noexcept;

		template <std::size_t N>
		constexpr span(std::array<value_type, N>& arr) noexcept;

		template <std::size_t N>
		constexpr span(const std::array<value_type, N>& arr) noexcept;

		template <class Container>
		constexpr span(Container& cont);

		template <class Container>
		constexpr span(const Container& cont);

		constexpr span(const span& other) noexcept = default;

		//**********************************************************
		constexpr pointer data() const noexcept;
		constexpr pointer end() const ;
		constexpr pointer begin() const ;
		constexpr reference operator[](index_type idx) const noexcept;

		constexpr index_type size() const noexcept;

		constexpr reference front() const;
		constexpr reference back() const;
		constexpr bool empty() const noexcept;

		constexpr span& operator=(const span& other) noexcept = default;

	private:
			pointer m_data;

			/// in case if Extent template parameter is set to a flag value that means the number of elements is runtime, not compiletime, then this variable holds the number of elements.
			index_type m_number_of_elements;

};

template<class T , std::size_t Extent>
constexpr span<T , Extent>::span(span::pointer ptr, span::index_type count)
		:m_data(ptr) , m_number_of_elements(count)
{

}

template<class T , std::size_t Extent>
constexpr span<T , Extent>::span(span::pointer first, span::pointer last)
		:m_data(first) , m_number_of_elements(last-first)
{

}

template<class T , std::size_t Extent>
constexpr typename span<T , Extent>::pointer span<T , Extent>::data() const noexcept
{
		return m_data;
}

template<class T , std::size_t Extent>
constexpr typename span<T , Extent>::reference span<T , Extent>::operator[](index_type idx) const noexcept {
        return * ( m_data + idx );
}

template<class T , std::size_t Extent>
constexpr typename span<T , Extent>::pointer span<T , Extent>::begin() const
{
		return m_data;
}

template<class T , std::size_t Extent>
constexpr typename span<T , Extent>::pointer span<T , Extent>::end() const
{
		return (m_data + m_number_of_elements);
}

template<class T , std::size_t Extent>
constexpr  typename span<T , Extent>::index_type span<T , Extent>::size() const noexcept
{
		if (Extent != dynamic_extent) return Extent; 
		return m_number_of_elements;
}

template<class T , std::size_t Extent>
constexpr typename span<T , Extent>::reference span<T , Extent>::front() const
{
		return *m_data;
}

template<class T , std::size_t Extent>
constexpr typename span<T , Extent>::reference span<T , Extent>::back() const
{
	return *(m_data + m_number_of_elements - 1);

}

template<class T , std::size_t Extent>
constexpr bool span<T , Extent>::empty() const noexcept
{
	return (size() == 0);
}

template<class T , std::size_t Extent>
template<std::size_t N>
constexpr span<T , Extent>::span(span::element_type (&arr)[N]) noexcept
		: m_data(&arr[0]) , m_number_of_elements(N)
{

}

template<class T , std::size_t Extent>
template<std::size_t N >
constexpr span<T , Extent>::span(std::array< span::value_type, N> &arr) noexcept
		:m_data(arr.data()), m_number_of_elements(arr.size())
{

}

template<class T , std::size_t Extent>
template<std::size_t N >
constexpr span<T , Extent>::span(const std::array< span::value_type, N> &arr) noexcept
		:m_data(arr.data()), m_number_of_elements(arr.size())
{

}

template<class T , std::size_t Extent>
template<class Container>
constexpr span<T , Extent>::span(Container &cont)
		:m_data(cont.data()) , m_number_of_elements(cont.size())
{

}

template<class T , std::size_t Extent>
template<class Container>
constexpr span<T , Extent>::span(const Container &cont)
		:m_data(cont.data()) , m_number_of_elements(cont.size())
{

}

#endif // SPAN_HPP
