package com.detroitauctionshippers.service;

import java.util.Set;

import com.detroitauctionshippers.domain.AppUser;
import com.detroitauctionshippers.domain.PasswordResetToken;
import com.detroitauctionshippers.domain.UserRole;

public interface UserService {
	AppUser createUser(AppUser user, Set<UserRole> userRoles) throws Exception;

	AppUser save(AppUser user);

	AppUser findByUsername(String username);

	AppUser findByEmail(String userEmail);

	PasswordResetToken getPasswordResetToken(final String token);

	void createPasswordResetTokenForUser(final AppUser user, final String token);
}
