package com.example;

import java.util.ArrayList;
import java.util.List;
import org.apache.tomcat.jdbc.pool.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

@Configuration
@EnableWebMvcSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private DataSource datasource;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        JdbcUserDetailsManager userDetailsService = new JdbcUserDetailsManager();
        userDetailsService.setDataSource(datasource);
//        userDetailsService.setDataSource(datasource);
        PasswordEncoder encoder = new BCryptPasswordEncoder();

        auth.userDetailsService(userDetailsService).passwordEncoder(encoder);
        auth.jdbcAuthentication().dataSource(datasource);
        auth.getDefaultUserDetailsService();
//        auth.jdbcAuthentication().dataSource(datasource);

        if(!userDetailsService.userExists("user")) {
            List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
            authorities.add(new SimpleGrantedAuthority("USER"));
            User userDetails = new User("user", encoder.encode("password"), authorities);

            userDetailsService.createUser(userDetails);
        }
    }
}