package com.detroitauctionshippers.service;

import java.util.Set;

import com.detroitauctionshippers.domain.AppUser;
import com.detroitauctionshippers.domain.UserRole;



public interface UserService {
	AppUser createUser(AppUser user, Set<UserRole> userRoles) throws Exception;
	
	AppUser save(AppUser user);
}
