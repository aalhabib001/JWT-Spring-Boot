package com.habib.securityproject.securityproject.repository;

import com.habib.securityproject.securityproject.model.Role;
import com.habib.securityproject.securityproject.model.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    // Optional<Role> findByName(RoleName roleName);
    Optional<Role> findByName(RoleName role);
}