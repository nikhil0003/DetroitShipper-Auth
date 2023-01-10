package com.detroitauctionshippers.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class UserController {
	
	@GetMapping("/login")
	public String login() {
		return "login";
	}

//	@PostMapping("/login")
//	public String loginFailed() {
//		return "redirect:/authenticate?error=invalid username or password";
//	}
}
