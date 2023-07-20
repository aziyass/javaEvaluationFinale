package org.sid.ebankingbackend.security;


import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configurable
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public InMemoryUserDetailsManager memoryUserDetailsManager(){
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        /*UserDetails user = User.withUsername("user1").password(encoder.encode("12345")).roles("USER").build();
        return new InMemoryUserDetailsManager (user);*/
        return new InMemoryUserDetailsManager(
                User.withUsername("user1").password(encoder.encode("12345")).authorities("USER").build(),
                User.withUsername("admin").password(encoder.encode("12345")).authorities("USER","ADMIN").build()
        );
    }

    //@Bean
    /*public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }*/

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .sessionManagement(sm->sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf->csrf.disable())
                .authorizeHttpRequests(ar->ar.anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .build();
    }


}
