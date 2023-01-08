package com.detroitauctionshippers.service;

import java.util.Set;

import com.detroitauctionshippers.domain.User;
import com.detroitauctionshippers.domain.UserRole;



public interface UserService {
	User createUser(User user, Set<UserRole> userRoles) throws Exception;
	
	User save(User user);
}
