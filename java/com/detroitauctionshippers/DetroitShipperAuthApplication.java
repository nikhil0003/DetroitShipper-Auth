package com.detroitauctionshippers;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.CrossOrigin;

@CrossOrigin("http://127.0.0.1:3000")
@SpringBootApplication
public class DetroitShipperAuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(DetroitShipperAuthApplication.class, args);
	}

}
