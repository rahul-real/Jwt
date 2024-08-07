package com.security.jwt.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import lombok.extern.slf4j.Slf4j;

@RequestMapping("/jwt")
@Controller
@Slf4j
public class JwtController {
	
	@GetMapping("/helloWorld")
	public String helloWorld(Model model) {
		log.debug("Debug level");
		log.info("INFO Level");
		return "Hello World";
//		model.addAttribute("message", "Hello, World!");
//		return "greeting";
	}
	
    @GetMapping("/greeting")
    public String greeting(@RequestParam(required=false, defaultValue="World") String name, Model model) {
        model.addAttribute("name", name);
        return "greeting";
    }

}

