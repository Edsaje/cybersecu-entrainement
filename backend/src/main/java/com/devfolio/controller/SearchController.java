package com.devfolio.controller;

import com.devfolio.model.Project;
import com.devfolio.repository.ProjectRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/search")
public class SearchController {

    @Autowired
    private ProjectRepository projectRepository;

    @GetMapping("/projects")
    public ResponseEntity<List<Project>> searchProjects(@RequestParam(required = false, defaultValue = "") String q) {
        return ResponseEntity.ok(projectRepository.searchPublicProjects(q));
    }
}