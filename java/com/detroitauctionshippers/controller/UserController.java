package com.detroitauctionshippers.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
	
	@GetMapping(value = "/add")
	public String helloMethod() {
		return "hello";
	}
}
