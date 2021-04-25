package com.gigatorb.jwt.controller;

import com.gigatorb.jwt.model.JwtRequest;
import com.gigatorb.jwt.model.JwtResponse;
import com.gigatorb.jwt.service.CustomUserDetailsService;
import com.gigatorb.jwt.util.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @Autowired
    private JWTUtil jwtUtil;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @GetMapping("/home")
    public String home(){
        return "Welcome, This is user page.";
    }

    @GetMapping("/admin")
    public String admin(){
        return "Welcome, This is admin page.";
    }

    @PostMapping("/authenticate")
    public JwtResponse authenticate(@RequestBody JwtRequest jwtRequest) throws Exception{
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            jwtRequest.getUsername(),
                            jwtRequest.getPassword()
                    )
            );
        }catch (BadCredentialsException ex){
            throw new Exception("Bad Credential Exception", ex);
        }

        final UserDetails userDetails = customUserDetailsService.loadUserByUsername(
                jwtRequest.getUsername());
        final String token = jwtUtil.generateToken(userDetails);

        return new JwtResponse(token);
    }
}
