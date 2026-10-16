package com.devfolio.controller;                                                                                                                                                 
                                                                                                                                                                                     
    import com.devfolio.model.Project;                                                                                                                                               
    import com.devfolio.repository.ProjectRepository;                                                                                                                                
    import com.devfolio.service.JwtService;                                                                                                                                          
    import io.jsonwebtoken.Claims;                                                                                                                                                   
    import org.springframework.beans.factory.annotation.Autowired;                                                                                                                   
    import org.springframework.http.HttpStatus;                                                                                                                                      
    import org.springframework.http.ResponseEntity;                                                                                                                                  
    import org.springframework.web.bind.annotation.*;                                                                                                                                
                                                                                                                                                                                     
    import java.net.URL;                                                                                                                                                             
    import java.util.List;                                                                                                                                                           
    import java.util.Map;                                                                                                                                                            
                                                                                                                                                                                     
    @RestController                                                                                                                                                                  
    @RequestMapping("/api/projects")                                                                                                                                                 
    public class ProjectController {                                                                                                                                                 
                                                                                                                                                                                     
        @Autowired                                                                                                                                                                   
        private ProjectRepository projectRepository;                                                                                                                                 
                                                                                                                                                                                     
        @Autowired                                                                                                                                                                   
        private JwtService jwtService;                                                                                                                                               
                                                                                                                                                                                     
        @GetMapping                                                                                                                                                                  
        public ResponseEntity<List<Project>> getAllProjects() {                                                                                                                      
            return ResponseEntity.ok(projectRepository.findByIsPublicTrue());                                                                                                        
        }                                                                                                                                                                            
                                                                                                                                                                                     
        @GetMapping("/{id}")                                                                                                                                                         
        public ResponseEntity<Project> getProject(@PathVariable Long id) {                                                                                                           
            return projectRepository.findById(id)                                                                                                                                    
                    .map(ResponseEntity::ok)                                                                                                                                         
                    .orElse(ResponseEntity.notFound().build());                                                                                                                      
        }                                                                                                                                                                            
                                                                                                                                                                                     
        @PostMapping                                                                                                                                                                 
        public ResponseEntity<?> createProject(                                                                                                                                      
                @RequestBody Project project,                                                                                                                                        
                @RequestHeader(value = "Authorization", required = false) String authHeader) {                                                                                       
                                                                                                                                                                                     
            Claims claims = extractClaims(authHeader);                                                                                                                               
            if (claims == null) {                                                                                                                                                    
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();                                                                                                       
            }                                                                                                                                                                        
                                                                                                                                                                                     
            // On force le ownerId avec l'ID réel issu du token (évite de créer un projet au nom d'un autre)                                                                         
            Long currentUserId = claims.get("userId", Number.class).longValue();                                                                                                     
            project.setOwnerId(currentUserId);                                                                                                                                       
                                                                                                                                                                                     
            return ResponseEntity.ok(projectRepository.save(project));                                                                                                               
        }                                                                                                                                                                            
                                                                                                                                                                                     
        @PutMapping("/{id}")                                                                                                                                                         
        public ResponseEntity<?> updateProject(                                                                                                                                      
                @PathVariable Long id,                                                                                                                                               
                @RequestBody Project updated,                                                                                                                                        
                @RequestHeader(value = "Authorization", required = false) String authHeader) {                                                                                       
                                                                                                                                                                                     
            Claims claims = extractClaims(authHeader);                                                                                                                               
            if (claims == null) {                                                                                                                                                    
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();                                                                                                       
            }                                                                                                                                                                        
                                                                                                                                                                                     
            Long currentUserId = claims.get("userId", Number.class).longValue();                                                                                                     
            String role = claims.get("role", String.class);                                                                                                                          
                                                                                                                                                                                     
            return projectRepository.findById(id).map(project -> {                                                                                                                   
                // Seul le propriétaire ou un ADMIN peut modifier                                                                                                                    
                if (!project.getOwnerId().equals(currentUserId) && !"ADMIN".equals(role)) {                                                                                          
                    return ResponseEntity.status(HttpStatus.FORBIDDEN).build();                                                                                                      
                }                                                                                                                                                                    
                                                                                                                                                                                     
                project.setTitle(updated.getTitle());                                                                                                                                
                project.setDescription(updated.getDescription());                                                                                                                    
                project.setGithubUrl(updated.getGithubUrl());                                                                                                                        
                project.setImageUrl(updated.getImageUrl());                                                                                                                          
                project.setIsPublic(updated.getIsPublic());                                                                                                                          
                return ResponseEntity.ok(projectRepository.save(project));                                                                                                           
            }).orElse(ResponseEntity.notFound().build());                                                                                                                            
        }                                                                                                                                                                            
                                                                                                                                                                                     
        @DeleteMapping("/{id}")                                                                                                                                                      
        public ResponseEntity<?> deleteProject(                                                                                                                                      
                @PathVariable Long id,                                                                                                                                               
                @RequestHeader(value = "Authorization", required = false) String authHeader) {                                                                                       
                                                                                                                                                                                     
            Claims claims = extractClaims(authHeader);                                                                                                                               
            if (claims == null) {                                                                                                                                                    
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();                                                                                                       
            }                                                                                                                                                                        
                                                                                                                                                                                     
            Long currentUserId = claims.get("userId", Number.class).longValue();                                                                                                     
            String role = claims.get("role", String.class);                                                                                                                          
                                                                                                                                                                                     
            return projectRepository.findById(id).map(project -> {                                                                                                                   
                // Seul le propriétaire ou un ADMIN peut supprimer                                                                                                                   
                if (!project.getOwnerId().equals(currentUserId) && !"ADMIN".equals(role)) {                                                                                          
                    return ResponseEntity.status(HttpStatus.FORBIDDEN).build();                                                                                                      
                }                                                                                                                                                                    
                                                                                                                                                                                     
                projectRepository.delete(project);                                                                                                                                   
                return ResponseEntity.ok().build();                                                                                                                                  
            }).orElse(ResponseEntity.notFound().build());                                                                                                                            
        }                                                                                                                                                                            
                                                                                                                                                                                     
        // Méthode utilitaire pour extraire et valider le token                                                                                                                      
        private Claims extractClaims(String authHeader) {                                                                                                                            
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {                                                                                                           
                return null;                                                                                                                                                         
            }                                                                                                                                                                        
            try {                                                                                                                                                                    
                return jwtService.validateToken(authHeader.substring(7));                                                                                                            
            } catch (Exception e) {                                                                                                                                                  
                return null;                                                                                                                                                         
            }                                                                                                                                                                        
        }                                                                                                                                                                            
    }