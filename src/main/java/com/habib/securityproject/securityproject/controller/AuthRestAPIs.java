package com.habib.securityproject.securityproject.controller;

import com.habib.securityproject.securityproject.dto.request.LoginForm;
import com.habib.securityproject.securityproject.dto.request.SignUpForm;
import com.habib.securityproject.securityproject.dto.response.IdentityResponse;
import com.habib.securityproject.securityproject.services.SignUpAndSignInService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@Slf4j
@CrossOrigin(origins = "*" , maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthRestAPIs {

    @Autowired
    private SignUpAndSignInService signUpAndSignInService;


    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginForm loginRequest) {

        return ResponseEntity.ok(signUpAndSignInService.signIn(loginRequest));
    }

    @PostMapping("/signup")
    public IdentityResponse registerUser(@RequestBody SignUpForm signUpRequest) {
        return signUpAndSignInService.signUp(signUpRequest);
    }
    @GetMapping("/users")
    public String getLoggedAuthId() {
        return signUpAndSignInService.getLoggedAuthUser();
    }

}