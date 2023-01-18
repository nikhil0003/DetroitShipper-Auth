package com.detroitauctionshippers.repository;

import org.springframework.data.repository.CrudRepository;

import com.detroitauctionshippers.domain.AppUser;

public interface UserRepository extends CrudRepository<AppUser, Long> {
	AppUser findByUsername(String username);

	AppUser findByEmail(String userEmail);
}
