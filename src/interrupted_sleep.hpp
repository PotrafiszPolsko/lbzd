#ifndef INTERRUPTED_SLEEP_HPP
#define INTERRUPTED_SLEEP_HPP

#include <chrono>
#include <condition_variable>

/**
 * @brief The c_interrupted_sleep class
 * This class provides an interruptible sleep functionality. One thread sleeps for some duration of time (or infinity)
 * and second thread can interrupt this sleep using wake_up() method. wake_up() has no effect on future sleeps and
 * breaks only active sleeps.
 *
 * Example pseudocode:
 *
 * c_interrupted_sleep sleeper;
 * thread_1 {
 *     // this function unblocks thread after 10 seconds or when wake_up() method is called
 *     // we can also call here sleep_infinity() if we want only wait for wake_up() without timeout
 *     sleeper.sleep_for(10 seconds)
 * }
 * thread_2 {
 *     sleeper.wake_up();
 * }
 */
class c_interrupted_sleep {
	private:
		std::condition_variable m_cv;
		std::mutex m_mutex;
	public:
		void sleep_for(const std::chrono::seconds & sleep_time); ///< [threadsafe]
		void wake_up(); ///< [threadsafe]
};

#endif // INTERRUPTED_SLEEP_HPP
