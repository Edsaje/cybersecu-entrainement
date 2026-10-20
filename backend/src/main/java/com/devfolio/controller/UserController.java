package com.devfolio.controller;                                                                                                                                                 
                                                                                                                                                                                     
    import com.devfolio.model.User;                                                                                                                                                  
    import com.devfolio.repository.UserRepository;                                                                                                                                   
    import com.devfolio.service.JwtService;                                                                                                                                          
    import io.jsonwebtoken.Claims;                                                                                                                                                   
    import org.springframework.beans.factory.annotation.Autowired;                                                                                                                   
    import org.springframework.http.HttpStatus;                                                                                                                                      
    import org.springframework.http.ResponseEntity;                                                                                                                                  
    import org.springframework.web.bind.annotation.*;                                                                                                                                
                                                                                                                                                                                     
import java.util.List;
import java.util.Map;
import java.util.Optional;                                                                                                                                                           
                                                                                                                                                                                     
    @RestController                                                                                                                                                                  
    @RequestMapping("/api")                                                                                                                                                          
    public class UserController {                                                                                                                                                    
                                                                                                                                                                                     
        @Autowired                                                                                                                                                                   
        private UserRepository userRepository;                                                                                                                                       
                                                                                                                                                                                     
        @Autowired                                                                                                                                                                   
        private JwtService jwtService;                                                                                                                                               
                                                                                                                                                                                     
        @GetMapping("/admin/users")                                                                                                                                                  
        public ResponseEntity<?> getAllUsers(@RequestHeader(value = "Authorization", required = false) String authHeader) {                                                          
            Claims claims = extractClaims(authHeader);                                                                                                                               
            if (claims == null || !"ADMIN".equals(claims.get("role", String.class))) {                                                                                               
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();                                                                                                          
            }                                                                                                                                                                        
            return ResponseEntity.ok(userRepository.findAll());                                                                                                                      
        }                                                                                                                                                                            
                                                                                                                                                                                     
        @GetMapping("/users/{id}")                                                                                                                                                   
        public ResponseEntity<User> getUser(@PathVariable Long id) {                                                                                                                 
            return userRepository.findById(id)                                                                                                                                       
                    .map(ResponseEntity::ok)                                                                                                                                         
                    .orElse(ResponseEntity.notFound().build());                                                                                                                      
        }                                                                                                                                                                            
                                                                                                                                                                                     
        @PutMapping("/users/{id}")                                                                                                                                                   
        public ResponseEntity<?> updateUser(                                                                                                                                         
                @PathVariable Long id,                                                                                                                                               
                @RequestBody User updated,                                                                                                                                           
                @RequestHeader(value = "Authorization", required = false) String authHeader) {                                                                                       
                                                                                                                                                                                     
            Claims claims = extractClaims(authHeader);                                                                                                                               
            if (claims == null) {                                                                                                                                                    
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();                                                                                                       
            }                                                                                                                                                                        
                                                                                                                                                                                     
            Long currentUserId = claims.get("userId", Number.class).longValue();                                                                                                     
            String currentUserRole = claims.get("role", String.class);                                                                                                               
                                                                                                                                                                                     
            // Seul l'utilisateur lui-même ou un ADMIN peut modifier le profil                                                                                                       
            if (!id.equals(currentUserId) && !"ADMIN".equals(currentUserRole)) {                                                                                                     
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();                                                                                                          
            }                                                                                                                                                                        
                                                                                                                                                                                     
            return userRepository.findById(id).map(user -> {
                // VULN-12 : Vérifier que le nouvel email n'est pas déjà pris par un tiers
                if (updated.getEmail() != null && !updated.getEmail().equals(user.getEmail())) {
                    Optional<User> existing = userRepository.findByEmail(updated.getEmail());
                    if (existing.isPresent() && !existing.get().getId().equals(id)) {
                        return ResponseEntity.status(HttpStatus.CONFLICT)
                                .body(Map.of("error", "Cet email est déjà utilisé par un autre compte"));
                    }
                    user.setEmail(updated.getEmail());
                }
                user.setBio(updated.getBio());

                // VULN-10 (Mass Assignment) : Seul un ADMIN a le droit de changer le rôle
                if ("ADMIN".equals(currentUserRole) && updated.getRole() != null) {
                    user.setRole(updated.getRole());
                }

                return ResponseEntity.ok(userRepository.save(user));
            }).orElse(ResponseEntity.notFound().build());                                                                                                                            
        }                                                                                                                                                                            
  
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