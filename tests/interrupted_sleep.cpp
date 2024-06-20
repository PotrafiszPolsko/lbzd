#include <gtest/gtest.h>
#include "../src/interrupted_sleep.hpp"
#include <thread>

TEST(interrupted_sleep, sleep_for) {
	c_interrupted_sleep sleep;
	const auto time = std::chrono::seconds(3);
	const auto start = std::chrono::steady_clock::now();
	sleep.sleep_for(time);
	const auto end = std::chrono::steady_clock::now();
	const auto diff_time = std::chrono::duration_cast<std::chrono::seconds>(end - start);
	EXPECT_EQ(time, diff_time);
}

TEST(interrupted_sleep, wake_up) {
	c_interrupted_sleep sleep;
	std::condition_variable cv;
	const auto time = std::chrono::seconds(10);
	const auto start = std::chrono::steady_clock::now();
	std::mutex mtx;
	bool is_wake_up = false;
	std::thread waking([&cv, &mtx, &sleep, &is_wake_up](){
		std::unique_lock<std::mutex> lock(mtx);
		cv.wait(lock, [&is_wake_up](){return is_wake_up;});
		std::this_thread::sleep_for(std::chrono::seconds(1));
		sleep.wake_up();
	});
	std::thread sleeping([&cv, &mtx, &sleep, &time, &is_wake_up](){
		std::unique_lock<std::mutex> lock(mtx);
		is_wake_up = true;
		lock.unlock();
		cv.notify_one();
		sleep.sleep_for(time);
	});
	waking.join();
	sleeping.join();
	const auto end = std::chrono::steady_clock::now();
	const auto diff_time = std::chrono::duration_cast<std::chrono::seconds>(end - start);
	EXPECT_EQ(1, diff_time.count());
}
