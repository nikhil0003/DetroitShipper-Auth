package com.detroitauctionshippers.repository;

import org.springframework.data.repository.CrudRepository;

import com.detroitauctionshippers.domain.Role;


public interface RoleRepository extends CrudRepository<Role, Long> {
	Role findByname(String name);
}
