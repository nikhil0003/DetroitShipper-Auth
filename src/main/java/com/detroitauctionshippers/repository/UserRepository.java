package com.detroitauctionshippers.repository;

import org.springframework.data.repository.CrudRepository;

import com.detroitauctionshippers.domain.User;

public interface UserRepository extends CrudRepository<User, Long> {
	User findByUsername(String username);
}
