
package org.anyframejava.search;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

@SpringBootApplication
@EnableRedisHttpSession
@EnableDiscoveryClient
public class SearchApplication extends WebSecurityConfigurerAdapter {
	
	public static void main(String[] args) {
		
		SpringApplication.run(SearchApplication.class, args);
		
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http
				.httpBasic()
				.and()
				.authorizeRequests()
				.antMatchers(HttpMethod.GET, "/search/**").anonymous()
				.antMatchers(HttpMethod.POST, "/search/**").permitAll()
				.antMatchers(HttpMethod.PUT, "/search/**").permitAll()
				.anyRequest().authenticated();
	}
	
}
