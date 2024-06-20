#include "interrupted_sleep.hpp"

void c_interrupted_sleep::sleep_for(const std::chrono::seconds &sleep_time) {
	std::unique_lock<std::mutex> lock(m_mutex);
	m_cv.wait_for(lock, sleep_time);
}

void c_interrupted_sleep::wake_up() {
	m_cv.notify_all();
}
