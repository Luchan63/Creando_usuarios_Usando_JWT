package com.example.repository;

import com.example.models.RolleEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RolesRepository extends CrudRepository<RolleEntity,Long> {
}
