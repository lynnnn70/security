package com.lynnnn.security.config;

import com.lynnnn.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository repository;


    @Bean
    public UserDetailsService userDetailsService() {
        return username -> null
        }
    }
}
