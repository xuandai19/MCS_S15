package org.example.courseservice.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@RestController
@RequestMapping("/api/courses")
public class CourseController {

    private final Map<Long, String> courses = new ConcurrentHashMap<>();
    private final AtomicLong idGen = new AtomicLong(1);

    public CourseController() {
        courses.put(1L, "Course A - Introduction to Microservices");
        courses.put(2L, "Course B - Spring Security JWT");
    }

    // GET: requires COURSE_READ
    @GetMapping
    @PreAuthorize("hasAuthority('COURSE_READ')")
    public ResponseEntity<List<Map.Entry<Long, String>>> getAll() {
        return ResponseEntity.ok(new ArrayList<>(courses.entrySet()));
    }

    // POST: requires COURSE_WRITE
    @PostMapping
    @PreAuthorize("hasAuthority('COURSE_WRITE')")
    public ResponseEntity<?> create(@RequestBody Map<String, String> body) {
        long id = idGen.getAndIncrement();
        String name = body.getOrDefault("name", "New Course");
        courses.put(id, name);
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("id", id, "name", name));
    }
}
