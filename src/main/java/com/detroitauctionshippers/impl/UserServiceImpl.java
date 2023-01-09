package com.detroitauctionshippers.impl;

import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.detroitauctionshippers.domain.AppUser;
import com.detroitauctionshippers.domain.UserRole;
import com.detroitauctionshippers.repository.RoleRepository;
import com.detroitauctionshippers.repository.UserRepository;
import com.detroitauctionshippers.service.UserService;

@Service
public class UserServiceImpl implements UserService {

	private static final Logger LOG = LoggerFactory.getLogger(UserService.class);
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private RoleRepository roleRepository;

	@Override
	public AppUser createUser(AppUser user, Set<UserRole> userRoles) {
		AppUser localUser = userRepository.findByUsername(user.getUsername());

		if (localUser != null) {
			LOG.info("user {} already exists. Nothing will be done.", user.getUsername());
		} else {
			for (UserRole ur : userRoles) {
				roleRepository.save(ur.getRole());
			}

			user.getUserRoles().addAll(userRoles);

			localUser = userRepository.save(user);
		}

		return localUser;
	}

	@Override
	public AppUser save(AppUser user) {
		return userRepository.save(user);
	}

}
