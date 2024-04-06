package com.example;

import com.example.models.ERole;
import com.example.models.RolleEntity;
import com.example.models.UserEntity;
import com.example.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Set;

@SpringBootApplication
public class SpringSecurityJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityJwtApplication.class, args);
	}

	@Autowired
	PasswordEncoder passwordEncoder;

	@Autowired
	UserRepository userRepository;
	@Bean
	CommandLineRunner init()
	{
		return args -> {

			UserEntity userEntity = UserEntity.builder()
					.email("luis@gmail.com")
					.username("luisfiguereo")
					.password(passwordEncoder.encode("1234"))
					.roles(Set.of(RolleEntity.builder()
							.name(ERole.valueOf(ERole.ADMIM.name()))
							.build()))
					.build();

			UserEntity userEntity1 = UserEntity.builder()
					.email("luis@gmail.com")
					.username("luisfiguereo1")
					.password(passwordEncoder.encode("1234"))
					.roles(Set.of(RolleEntity.builder()
							.name(ERole.valueOf(ERole.USER.name()))
							.build()))
					.build();

			UserEntity userEntity2 = UserEntity.builder()
					.email("luis@gmail.com")
					.username("luisfiguereo2")
					.password(passwordEncoder.encode("1234"))
					.roles(Set.of(RolleEntity.builder()
							.name(ERole.valueOf(ERole.INVITED.name()))
							.build()))
					.build();


			userRepository.saveAll(List.of(userEntity,userEntity1,userEntity2));

		};
	}


}
