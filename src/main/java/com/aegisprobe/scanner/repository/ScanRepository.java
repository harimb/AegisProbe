package com.aegisprobe.scanner.repository;

import com.aegisprobe.scanner.domain.Scan;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ScanRepository extends JpaRepository<Scan, Long> {

    List<Scan> findAllByOrderByStartedAtDesc();
}
