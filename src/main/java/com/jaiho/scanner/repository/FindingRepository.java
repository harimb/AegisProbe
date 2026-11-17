package com.jaiho.scanner.repository;

import com.jaiho.scanner.domain.Finding;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

public interface FindingRepository extends JpaRepository<Finding, Long> {

    List<Finding> findByScanId(Long scanId);

    long countByScanId(Long scanId);
}
