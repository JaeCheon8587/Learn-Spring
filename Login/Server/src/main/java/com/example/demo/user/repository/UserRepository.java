package com.example.demo.user.repository;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.demo.user.entity.StdUser;

@Repository
public interface UserRepository extends JpaRepository<StdUser, Long>{
    Optional<StdUser> findByNameAndPersonalNumber(String name, String personalNumber);
    Optional<StdUser> findByIdAndNameAndPersonalNumber(String id, String name, String personalNumber);
    Optional<StdUser> findByIdAndPassword(String id, String password);
    Optional<StdUser> findById(String id);
}
