package com.habib.securityproject.securityproject.services;


import com.habib.securityproject.securityproject.dto.request.LoginForm;
import com.habib.securityproject.securityproject.dto.request.SignUpForm;
import com.habib.securityproject.securityproject.dto.response.IdentityResponse;
import com.habib.securityproject.securityproject.dto.response.JwtResponse;
import com.habib.securityproject.securityproject.model.Role;
import com.habib.securityproject.securityproject.model.RoleName;
import com.habib.securityproject.securityproject.model.User;
import com.habib.securityproject.securityproject.repository.RoleRepository;
import com.habib.securityproject.securityproject.repository.UserRepository;
import com.habib.securityproject.securityproject.security.jwt.JwtProvider;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.validation.ValidationException;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@AllArgsConstructor
@Service
public class SignUpAndSignInService {

    @Autowired
    PasswordEncoder encoder;
    @Autowired
    JwtProvider jwtProvider;
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;

    public IdentityResponse signUp(SignUpForm signUpRequest) {


        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            //TODO
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            //TODO
        }

        User user = new User();
        UUID id = UUID.randomUUID();
        String uuid = id.toString();
        user.setId(uuid);
        user.setName(signUpRequest.getName());
        user.setUsername(signUpRequest.getUsername());
        user.setEmail(signUpRequest.getEmail());
        user.setPassword(encoder.encode(signUpRequest.getPassword()));
        user.setRoles(getRolesOrThrow(signUpRequest.getRole()));
        userRepository.saveAndFlush(user);

        return new IdentityResponse(uuid);
    }


    public JwtResponse signIn(LoginForm loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtProvider.generateJwtToken(authentication);
        return new JwtResponse(jwt);
    }

    public String getLoggedAuthUser() {

        Object authUser = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Optional<String> loggedInAuthUserId = null;

        if (authUser instanceof UserDetails) {

            String username = ((UserDetails) authUser).getUsername();
            loggedInAuthUserId = userRepository.findAuthUsersById(username);


        } else if (authUser instanceof UserDetails == false) {
            throw new RuntimeException("LoggedIn user does not  account.");

        } else {
            String username = authUser.toString();

            System.out.println(username);
        }
        return loggedInAuthUserId.get();

    }


    private Set<Role> getRolesOrThrow(Set<String> roles2) {
        Set<Role> roles = new HashSet<>();
        for (String role : roles2) {
            Optional<Role> roleOptional = roleRepository.findByName(RoleName.valueOf(role));
            System.out.println(roleOptional.get());
            if (!roleOptional.isPresent()) {
                throw new ValidationException("Role '" + role + "' does not exist.");
            }
            roles.add(roleOptional.get());
        }
        return roles;
    }
}
