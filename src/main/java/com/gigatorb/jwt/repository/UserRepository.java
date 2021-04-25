package com.gigatorb.jwt.repository;

import com.gigatorb.jwt.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;


public interface UserRepository extends JpaRepository<User, Integer> {

    User findByUsername(String username);
}
