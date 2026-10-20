package com.lab.config;

import com.lab.security.PasswordService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SecurityConfig {
    @Bean
    public PasswordService passwordService() {
        return new PasswordService();
    }
}
