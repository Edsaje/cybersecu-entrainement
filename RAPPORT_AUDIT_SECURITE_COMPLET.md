# Rapport d'Audit de Sécurité Approfondi — DevFolio

**Cible :** Plateforme DevFolio (`/home/user/devfolio-audit`)  
**Type d'évaluation :** Audit en boîte blanche (revue de code statique, analyse d'architecture et vérifications d'API)  
**Référentiel :** OWASP Top 10:2021  
**Date :** 15 octobre 2026  

---

## 1. Résumé Exécutif

L'audit de sécurité mené sur l'application **DevFolio** a mis en évidence un niveau d'exposition très élevé. Plusieurs vulnérabilités critiques permettent d'ores et déjà à un utilisateur distant ou non authentifié de :
1. Récupérer l'intégralité des données en base (comptes, mots de passe, projets privés).
2. Prendre le contrôle complet de l'application et de son infrastructure.
3. Forcer le serveur backend à exécuter des requêtes internes non autorisées.
4. Exécuter du code malveillant sur les postes des utilisateurs via le navigateur.

### Répartition des vulnérabilités par criticité

```
[ CRITIQUE ] ██████████ (5)
[ ÉLEVÉ    ] ████████   (4)
[ MOYEN    ] ██████     (3)
[ FAIBLE   ] ████       (2)
```

---

## 2. Fiches Détaillées des Vulnérabilités

---

### VULN-01 : Injection SQL (SQLi) dans la recherche de projets
* **Identifiant :** CWE-89 / OWASP A03:2021 – Injection
* **Criticité :** **CRITIQUE** (CVSS v3.1 : 9.8)
* **Localisation :** [`backend/src/main/java/com/devfolio/controller/SearchController.java`](file:///home/user/devfolio-audit/backend/src/main/java/com/devfolio/controller/SearchController.java#L18-L26)

#### Explication technique
Dans `SearchController.java`, la méthode `searchProjects` prend un paramètre HTTP nommé `q` et le concatène directement dans une chaîne de requête SQL native (`createNativeQuery`) sans aucune étape de validation, d'échappement ou de paramétrage.

#### Preuve (Extrait de code source)
```java
// SearchController.java (lignes 19-25)
@GetMapping("/projects")
public ResponseEntity<?> searchProjects(@RequestParam String q) {
    String sql = "SELECT * FROM projects WHERE title LIKE '%" + q + "%' " +
                 "OR description LIKE '%" + q + "%'";

    @SuppressWarnings("unchecked")
    List<Project> results = entityManager.createNativeQuery(sql, Project.class).getResultList();
    return ResponseEntity.ok(results);
}
```

#### Impact théorique
Un attaquant peut injecter des structures SQL arbitraires (via `UNION SELECT`, des clauses booléennes ou des fonctions empilées) pour :
* Extraire l'intégralité de la base de données (notamment les tables `users` et les projets marqués `is_public = false`).
* Contourner les restrictions de visibilité.
* Selon les droits MariaDB, lire ou modifier des données du système.

#### Remédiation défensive
Remplacer la concaténation de chaînes par une requête paramétrée avec des paramètres nommés via Spring Data JPA :
```java
// Dans ProjectRepository.java
@Query("SELECT p FROM Project p WHERE (p.title LIKE %:q% OR p.description LIKE %:q%) AND p.isPublic = true")
List<Project> searchPublicProjects(@Param("q") String q);
```

---

### VULN-02 : Contrôle d'accès défaillant sur les routes d'administration et l'ensemble de l'API
* **Identifiant :** CWE-284 / CWE-306 / OWASP A01:2021 – Broken Access Control
* **Criticité :** **CRITIQUE** (CVSS v3.1 : 9.1)
* **Localisation :** [`backend/src/main/java/com/devfolio/config/SecurityConfig.java`](file:///home/user/devfolio-audit/backend/src/main/java/com/devfolio/config/SecurityConfig.java#L33-L38) et [`backend/src/main/java/com/devfolio/controller/UserController.java`](file:///home/user/devfolio-audit/backend/src/main/java/com/devfolio/controller/UserController.java#L18-L22)

#### Explication technique
Dans `SecurityConfig.java`, la configuration de la chaîne de filtres Spring Security autorise explicitement toutes les requêtes HTTP sans vérification d'authentification ni de rôle (`.anyRequest().permitAll()` et `.requestMatchers("/api/admin/**").permitAll()`).

#### Preuve (Vérification en direct)
L'envoi d'une requête HTTP `GET /api/admin/users` sans aucun jeton d'authentification (`Authorization`) renvoie un statut `200 OK` avec la liste complète des utilisateurs, de leurs rôles et de leurs empreintes de mot de passe :

```http
GET /api/admin/users HTTP/1.1
Host: localhost:8080

HTTP/1.1 200 OK
Content-Type: application/json

[
  {"id":1,"email":"admin@devfolio.com","password":"0192023a7bbd73250516f069df18b500","role":"ADMIN"},
  {"id":2,"email":"alice@student.com","password":"0192023a7bbd73250516f069df18b500","role":"USER"},
  {"id":3,"email":"bob@student.com","password":"0192023a7bbd73250516f069df18b500","role":"USER"}
]
```

#### Impact théorique
Divulgation complète et immédiate de l'annuaire des utilisateurs et de leurs identifiants sans nécessiter de compte valide.

#### Remédiation défensive
Configurer Spring Security pour exiger une authentification stricte et restreindre l'accès à l'administration :
```java
.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/auth/**").permitAll()
    .requestMatchers("/api/projects").permitAll()
    .requestMatchers("/api/admin/**").hasRole("ADMIN")
    .anyRequest().authenticated()
)
```

---

### VULN-03 : Contournement de signature JWT (Algorithme "None" / Tokens non signés)
* **Identifiant :** CWE-347 / OWASP A02:2021 – Cryptographic Failures & A07:2021
* **Criticité :** **CRITIQUE** (CVSS v3.1 : 9.8)
* **Localisation :** [`backend/src/main/java/com/devfolio/service/JwtService.java`](file:///home/user/devfolio-audit/backend/src/main/java/com/devfolio/service/JwtService.java#L39-L51)

#### Explication technique
La méthode `validateToken` intercepte les échecs de validation de signature. Dans son bloc `catch`, si le jeton comporte 2 parties (ou une 3ème partie vide, c'est-à-dire sans signature cryptographique), elle décode le payload et l'accepte aveuglément via `parseUnsignedClaims`.

#### Preuve (Extrait de code source)
```java
// JwtService.java (lignes 39-51)
} catch (Exception e) {
    String[] parts = token.split("\\.");
    if (parts.length == 2 || (parts.length == 3 && parts[2].isEmpty())) {
        try {
            String payload = new String(Base64.getDecoder().decode(parts[1]));
            return parseUnsignedClaims(payload);
        } catch (Exception ex) {
            throw e;
        }
    }
    throw e;
}
```

#### Impact théorique
N'importe quel client peut forger un jeton encodé en Base64 contenant `"role": "ADMIN"`, omettre la signature, et obtenir un accès avec les privilèges d'administrateur sans connaître la clé secrète.

#### Remédiation défensive
Supprimer intégralement le bloc de fallback non signé et rejeter tout jeton dont la signature cryptographique échoue :
```java
public Claims validateToken(String token) {
    return Jwts.parserBuilder()
            .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes()))
            .build()
            .parseClaimsJws(token)
            .getBody();
}
```

---

### VULN-04 : Exposition non authentifiée des points de terminaison Spring Boot Actuator
* **Identifiant :** CWE-200 / OWASP A05:2021 – Security Misconfiguration
* **Criticité :** **CRITIQUE** (CVSS v3.1 : 9.1)
* **Localisation :** [`backend/src/main/resources/application.properties`](file:///home/user/devfolio-audit/backend/src/main/resources/application.properties#L16-L20)

#### Explication technique
Le fichier de configuration active et expose l'ensemble des points d'administration Spring Boot Actuator (`management.endpoints.web.exposure.include=*`) sans exiger d'authentification (`management.security.enabled=false`).

#### Preuve (Vérification en direct)
L'interrogation de `GET /actuator` confirme l'exposition des routes sensibles :
* `/actuator/env` : retourne les variables d'environnement du serveur (clés d'API, chemins système).
* `/actuator/heapdump` : permet de télécharger une capture mémoire complète (contenant les mots de passe et clés déchiffrées).
* `/actuator/shutdown` : permet d'éteindre l'application à distance (déni de service).

#### Impact théorique
Fuite totale des secrets d'infrastructure et risque de déni de service immédiat.

#### Remédiation défensive
Restreindre Actuator au seul endpoint de santé (`health`) et le placer derrière une authentification forte :
```properties
management.endpoints.web.exposure.include=health,info
management.endpoint.health.show-details=never
```

---

### VULN-05 : Server-Side Request Forgery (SSRF) sur l'avatar et l'import de projets
* **Identifiant :** CWE-918 / OWASP A10:2021 – Server-Side Request Forgery
* **Criticité :** **ÉLEVÉE** (CVSS v3.1 : 8.6)
* **Localisation :** [`backend/src/main/java/com/devfolio/controller/AvatarController.java`](file:///home/user/devfolio-audit/backend/src/main/java/com/devfolio/controller/AvatarController.java#L19-L20) et [`backend/src/main/java/com/devfolio/controller/ProjectController.java`](file:///home/user/devfolio-audit/backend/src/main/java/com/devfolio/controller/ProjectController.java#L59-L63)

#### Explication technique
Les contrôleurs instancient un objet `URL` à partir d'une chaîne arbitraire transmise par le client et appellent immédiatement `.openStream().readAllBytes()` sans aucune validation de protocole, d'adresse IP ou de nom de domaine.

#### Preuve (Extrait de code source)
```java
// AvatarController.java (lignes 19-20)
URL avatarUrl = new URL(url);
byte[] imageData = avatarUrl.openStream().readAllBytes();
```
```java
// ProjectController.java (lignes 59-62)
@PostMapping("/import")
public ResponseEntity<?> importFromGithub(@RequestParam String githubUrl) throws Exception {
    URL url = new URL(githubUrl);
    String content = new String(url.openStream().readAllBytes());
    return ResponseEntity.ok(Map.of("content", content));
}
```

#### Impact théorique
Le serveur backend est contraint d'agir comme un proxy pour l'attaquant :
* Scan de ports et découverte des services internes du réseau Docker ou de la machine hôte (`http://localhost:3307`, `http://mariadb:3306`).
* Récupération des données sensibles depuis les endpoints internes (`http://localhost:8080/actuator/env`).
* Si déployé sur le cloud (AWS), interrogation du service de métadonnées d'instance (`http://169.254.169.254/latest/meta-data/`) pour voler les identifiants IAM temporaires.

#### Remédiation défensive
1. Imposer une liste blanche stricte de domaines autorisés (ex. uniquement `github.com` pour l'import).
2. Interdire formellement les protocoles autres que `https`.
3. Résoudre l'adresse IP de destination et bloquer les plages privées (RFC 1918 : `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`).

---

### VULN-06 : Contrôle d'accès au niveau des objets (IDOR / BOLA) sur les projets et profils
* **Identifiant :** CWE-639 / OWASP A01:2021 – Broken Access Control
* **Criticité :** **ÉLEVÉE** (CVSS v3.1 : 8.1)
* **Localisation :** [`backend/src/main/java/com/devfolio/controller/ProjectController.java`](file:///home/user/devfolio-audit/backend/src/main/java/com/devfolio/controller/ProjectController.java#L37-L56) et [`backend/src/main/java/com/devfolio/controller/UserController.java`](file:///home/user/devfolio-audit/backend/src/main/java/com/devfolio/controller/UserController.java#L31-L39)

#### Explication technique
Les endpoints de modification (`PUT /api/projects/{id}`) et suppression (`DELETE /api/projects/{id}`) acceptent l'identifiant de la ressource dans le chemin d'URL sans vérifier que l'utilisateur à l'origine de la requête est le propriétaire de cette ressource (`ownerId`). Le commentaire du code admet explicitement : `// Aucune vérification que le token correspond au propriétaire du projet`.

#### Preuve (Extrait de code source)
```java
// ProjectController.java (lignes 37-49)
@PutMapping("/{id}")
public ResponseEntity<Project> updateProject(
        @PathVariable Long id,
        @RequestBody Project updated,
        @RequestHeader(value = "Authorization", required = false) String token) {
    // Aucune vérification que le token correspond au propriétaire du projet
    return projectRepository.findById(id).map(project -> {
        project.setTitle(updated.getTitle());
        project.setDescription(updated.getDescription());
        return ResponseEntity.ok(projectRepository.save(project));
    }).orElse(ResponseEntity.notFound().build());
}
```

De même, `UserController.java` (ligne 35) permet à n'importe quel utilisateur de modifier le profil d'un autre via `PUT /api/users/{id}`, et exécute `user.setRole(updated.getRole())` (**Mass Assignment** permettant à un simple utilisateur de s'auto-attribuer le rôle `ADMIN`).

#### Impact théorique
Altération et suppression des données de tiers ; élévation de privilèges vers le statut d'administrateur.

#### Remédiation défensive
Extraire l'identifiant de l'utilisateur authentifié depuis le contexte de sécurité Spring et vérifier la propriété avant chaque modification :
```java
User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
if (!project.getOwnerId().equals(currentUser.getId())) {
    return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
}
```

---

### VULN-07 : Cross-Site Scripting stocké (Stored XSS) sur la biographie
* **Identifiant :** CWE-79 / OWASP A03:2021 – Injection
* **Criticité :** **ÉLEVÉE** (CVSS v3.1 : 7.5)
* **Localisation :** [`frontend/src/views/ProfileView.vue`](file:///home/user/devfolio-audit/frontend/src/views/ProfileView.vue#L33) et [`database/init.sql`](file:///home/user/devfolio-audit/database/init.sql#L28)

#### Explication technique
Dans `ProfileView.vue`, la biographie de l'utilisateur est injectée directement dans le DOM à l'aide de la directive `v-html="user.bio"`. Cette directive désactive l'échappement HTML natif de Vue.js.

#### Preuve (Extrait de code source)
```html
<!-- ProfileView.vue (ligne 33) -->
<div class="bio" v-html="user.bio"></div>
```
Dans `database/init.sql` (ligne 28), la présence de balises HTML non filtrées (`<h1>Admin</h1>`) confirme que la base stocke le HTML brut.

#### Impact théorique
Si un attaquant enregistre une charge utile contenant du code JavaScript dans son profil, le script s'exécute automatiquement dans la session de chaque utilisateur qui consulte sa page (vol de jetons stockés dans `localStorage`, requêtes frauduleuses à son insu).

#### Remédiation défensive
Remplacer la directive `v-html` par l'interpolation standard Vue.js qui neutralise les balises :
```html
<div class="bio">{{ user.bio }}</div>
```
Si le support de la mise en forme riche est requis, nettoyer le contenu côté client et serveur via une bibliothèque d'assainissement reconnue (ex. DOMPurify).

---

### VULN-08 : Hachage de mot de passe cryptographiquement défaillant (MD5 sans sel)
* **Identifiant :** CWE-328 / CWE-916 / OWASP A02:2021 – Cryptographic Failures
* **Criticité :** **ÉLEVÉE** (CVSS v3.1 : 7.4)
* **Localisation :** [`backend/src/main/java/com/devfolio/config/SecurityConfig.java`](file:///home/user/devfolio-audit/backend/src/main/java/com/devfolio/config/SecurityConfig.java#L48-L66) et [`backend/src/main/java/com/devfolio/service/AuthService.java`](file:///home/user/devfolio-audit/backend/src/main/java/com/devfolio/service/AuthService.java#L35-L43)

#### Explication technique
Les mots de passe sont hachés en utilisant l'algorithme MD5, sans sel cryptographique (*salt*). De surcroît, le bloc `catch` du `PasswordEncoder` renvoie la chaîne originale en cas d'erreur de hachage.

#### Preuve (Extrait de code source)
```java
// SecurityConfig.java (lignes 52-58)
try {
    MessageDigest md = MessageDigest.getInstance("MD5");
    byte[] hash = md.digest(raw.toString().getBytes());
    return HexFormat.of().formatHex(hash);
} catch (Exception e) {
    return raw.toString(); // Fuite en clair
}
```

#### Impact théorique
Les empreintes MD5 pré-calculées (*rainbow tables*) permettent de retrouver les mots de passe d'origine en quelques fractions de seconde.

#### Remédiation défensive
Instancier un encodeur standard de l'industrie avec coût adaptatif :
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);
}
```

---

### VULN-09 : Journalisation de mots de passe en clair et composants obsolètes
* **Identifiant :** CWE-532 / CWE-1104 / OWASP A09:2021 & A06:2021
* **Criticité :** **ÉLEVÉE** (CVSS v3.1 : 7.5)
* **Localisation :** [`backend/src/main/java/com/devfolio/controller/AuthController.java`](file:///home/user/devfolio-audit/backend/src/main/java/com/devfolio/controller/AuthController.java#L41-L43), [`backend/pom.xml`](file:///home/user/devfolio-audit/backend/pom.xml#L45-L48)

#### Explication technique
1. Dans `AuthController.java` (lignes 41 et 43), les mots de passe et noms d'utilisateurs saisis sont journalisés en clair :
   ```java
   log.info("Login attempt for user: " + username);
   log.debug("Password received: " + password);
   ```
2. Dans `pom.xml`, la bibliothèque `log4j-core` est présente en version `2.14.1`, version vulnérable à la faille critique **Log4Shell (CVE-2021-44228)** permettant l'exécution de code à distance via injection JNDI dans les messages journalisés.

#### Impact théorique
Compromission des mots de passe des utilisateurs dans les fichiers journaux (`devfolio.log`) et risque d'exécution de code arbitraire à distance via les données utilisateur envoyées dans les logs.

#### Remédiation défensive
* Supprimer immédiatement tout enregistrement de mot de passe dans les logs.
* Supprimer la dépendance explicite à `log4j-core 2.14.1` et utiliser le système de journalisation par défaut fourni et sécurisé par Spring Boot (`spring-boot-starter-logging` / Logback mis à jour).

---

### VULN-10 : Secrets et identifiants sensibles versionnés en clair
* **Identifiant :** CWE-798 / OWASP A05:2021 – Security Misconfiguration
* **Criticité :** **MOYENNE à ÉLEVÉE** (CVSS v3.1 : 6.8)
* **Localisation :** [`.env`](file:///home/user/devfolio-audit/.env) et [`docker-compose.yml`](file:///home/user/devfolio-audit/docker-compose.yml)

#### Explication technique
Le fichier `.env` contient des secrets réels ou simulés de production :
* Mot de passe administrateur par défaut : `admin123`
* Identifiants SMTP Google : `devfolio.noreply@gmail.com` / `MonMotDePasseGmail2024!`
* Clés d'API AWS : `AWS_ACCESS_KEY` / `AWS_SECRET_KEY`

#### Remédiation défensive
* Créer un fichier modèle `.env.example` sans valeurs sensibles.
* Ajouter immédiatement `.env` dans un fichier `.gitignore`.
* Révoquer et renouveler l'ensemble des identifiants et clés compromis.

---

### VULN-11 : Port de débogage JVM à distance (JDWP) exposé
* **Identifiant :** CWE-489 / OWASP A05:2021 – Security Misconfiguration
* **Criticité :** **MOYENNE** (CVSS v3.1 : 6.5)
* **Localisation :** [`backend/Dockerfile`](file:///home/user/devfolio-audit/backend/Dockerfile#L17-L19)

#### Explication technique
La commande de démarrage du conteneur active l'agent de débogage Java sur le port 5005 :
```dockerfile
EXPOSE 8080 5005
CMD ["java", "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005", "-jar", "app.jar"]
```
Le protocole JDWP ne dispose d'aucun mécanisme d'authentification native. Si le port venait à être publié sur l'hôte, n'importe quel client pourrait s'y connecter pour contrôler la JVM et exécuter du code arbitraire.

#### Remédiation défensive
Retirer l'argument `-agentlib:jdwp` de l'image de production et ne pas exposer le port 5005.

---

### VULN-12 : Déni de Service applicatif & Usurpation par absence d'unicité d'email
* **Identifiant :** CWE-20 / CWE-799 / OWASP A04:2021 – Insecure Design & A01:2021
* **Criticité :** **ÉLEVÉE** (CVSS v3.1 : 7.5)
* **Localisation :** [`database/init.sql`](file:///home/user/devfolio-audit/database/init.sql#L8) et [`backend/src/main/java/com/devfolio/controller/UserController.java`](file:///home/user/devfolio-audit/backend/src/main/java/com/devfolio/controller/UserController.java#L31-L39)

#### Explication technique
1. Dans `database/init.sql`, la colonne `email` de la table `users` est déclarée comme `email VARCHAR(255) NOT NULL`, sans contrainte d'unicité `UNIQUE`.
2. Dans `UserController.java`, l'endpoint de mise à jour `PUT /api/users/{id}` sauvegarde aveuglément le nouvel email sans vérifier s'il est déjà assigné à un autre compte (alors que `AuthController.register` effectuait ce contrôle).
3. Lors de la tentative de connexion d'un utilisateur, Spring Data JPA exécute `userRepository.findByEmail(email)`. Comme la méthode attend une valeur unique (`Optional<User>`), la présence de doublons en base lève l'exception `IncorrectResultSizeDataAccessException: query did not return a unique result: 2 results were returned`, provoquant un crash HTTP 500.

#### Preuve (Vérification en direct)
En modifiant l'email d'un utilisateur existant avec l'adresse d'un compte cible, MariaDB stocke deux lignes distinctes avec la même adresse. Toute tentative d'authentification ultérieure avec cette adresse échoue immédiatement avec un code `500 Internal Server Error`, bloquant définitivement l'accès du compte légitime.

#### Remédiation défensive
1. **Au niveau de la base de données (`init.sql`) :** Ajouter une contrainte `UNIQUE` sur la colonne `email` :
   ```sql
   email VARCHAR(255) NOT NULL UNIQUE,
   ```
2. **Au niveau de l'entité JPA (`User.java`) :** Annoter le champ :
   ```java
   @Column(nullable = false, unique = true)
   private String email;
   ```
3. **Au niveau de la couche contrôleur/service (`UserController.java`) :** Vérifier avant toute mise à jour que l'email n'appartient pas déjà à un autre identifiant utilisateur :
   ```java
   Optional<User> existing = userRepository.findByEmail(updated.getEmail());
   if (existing.isPresent() && !existing.get().getId().equals(id)) {
       return ResponseEntity.status(HttpStatus.CONFLICT).body("Email déjà utilisé");
   }
   ```

---

### VULN-13 : Énumération d'utilisateurs sur les formulaires d'authentification
* **Identifiant :** CWE-204 / OWASP A07:2021 – Identification and Authentication Failures
* **Criticité :** **MOYENNE** (CVSS v3.1 : 5.3)
* **Localisation :** [`backend/src/main/java/com/devfolio/controller/AuthController.java`](file:///home/user/devfolio-audit/backend/src/main/java/com/devfolio/controller/AuthController.java#L45-L54)

#### Explication technique
Dans `AuthController.java`, le contrôleur renvoie des messages d'erreur explicites et différenciés selon que l'adresse email existe ou non :
* Si l'email n'existe pas en base : `ResponseEntity.status(401).body(Map.of("error", "Utilisateur inconnu"))`
* Si l'email existe mais que le mot de passe est faux : `ResponseEntity.status(401).body(Map.of("error", "Mot de passe incorrect"))`
* Lors de l'inscription : `ResponseEntity.badRequest().body(Map.of("error", "Email déjà utilisé"))`

#### Preuve (Extrait de code source)
```java
// AuthController.java (lignes 45-54)
Optional<User> userOpt = userRepository.findByEmail(username);

if (userOpt.isEmpty()) {
    return ResponseEntity.status(401).body(Map.of("error", "Utilisateur inconnu"));
}

User user = userOpt.get();
if (!passwordEncoder.matches(password, user.getPassword())) {
    return ResponseEntity.status(401).body(Map.of("error", "Mot de passe incorrect"));
}
```

#### Impact théorique
Un attaquant peut automatiser l'envoi de requêtes avec un dictionnaire d'adresses email pour cartographier tous les utilisateurs inscrits. Une fois la liste des emails valides établie, il peut concentrer des attaques par force brute ou d'hameçonnage ciblé (*spear phishing*) sur ces comptes réels.

#### Remédiation défensive
1. **Unifier les messages d'erreur :** Utiliser un message générique identique, que l'email existe ou non :
   ```java
   if (userOpt.isEmpty() || !passwordEncoder.matches(password, userOpt.get().getPassword())) {
       return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Identifiants invalides"));
   }
   ```
2. **Mitigation temporelle :** S'assurer que le temps de traitement ne divulgue pas non plus l'existence du compte (ex. toujours exécuter un calcul de hachage factice même si l'utilisateur n'existe pas).
3. **Limitation de débit (*Rate Limiting*) :** Bloquer ou ralentir les requêtes après plusieurs échecs consécutifs depuis une même adresse IP.

---

### VULN-14 : Cross-Site Scripting basé sur le DOM (DOM XSS)
* **Identifiant :** CWE-79 / OWASP A03:2021 – Injection (XSS)
* **Criticité :** **ÉLEVÉE** (CVSS v3.1 : 7.2)
* **Localisation :** [`frontend/src/views/ProjectView.vue`](file:///home/user/devfolio-audit/frontend/src/views/ProjectView.vue#L13-L18)

#### Explication technique
Lors du chargement de la vue d'un projet, le composant extrait directement le paramètre `ref` de la chaîne de requête (`window.location.search`) et l'assigne à la propriété `.innerHTML` de l'élément `#ref-banner` sans neutralisation.

#### Preuve (Extrait de code source)
```javascript
// ProjectView.vue (lignes 13-18)
const refParam = new URLSearchParams(window.location.search).get('ref')
if (refParam) {
  const banner = document.getElementById('ref-banner')
  banner.style.display = 'block'
  banner.innerHTML = `Vous venez de : ${refParam}` // Injection directe dans le DOM
}
```

#### Impact théorique
Un attaquant peut diffuser une URL forgée (`http://localhost/project/1?ref=<img src=x onerror=...>`). Toute victime qui ouvre ce lien exécute le script malveillant dans le contexte de sa session sans que le serveur backend ne soit jamais sollicité.

#### Remédiation défensive
Remplacer l'affectation `innerHTML` par `textContent` qui traite la valeur strictement comme du texte brut :
```javascript
banner.textContent = `Vous venez de : ${refParam}`
```

---

### VULN-15 : Divulgation du jeton de réinitialisation de mot de passe dans la réponse API
* **Identifiant :** CWE-640 / OWASP A07:2021 – Identification and Authentication Failures
* **Criticité :** **ÉLEVÉE** (CVSS v3.1 : 8.1)
* **Localisation :** [`backend/src/main/java/com/devfolio/controller/AuthController.java`](file:///home/user/devfolio-audit/backend/src/main/java/com/devfolio/controller/AuthController.java#L74-L79)

#### Explication technique
L'endpoint de demande de réinitialisation de mot de passe génère un jeton secret UUID mais le renvoie directement dans le corps de réponse JSON au lieu de l'expédier par courrier électronique :
```java
// AuthController.java (lignes 74-79)
@PostMapping("/reset-password/request")
public ResponseEntity<?> requestReset(@RequestParam String email) {
    String token = UUID.randomUUID().toString();
    String resetUrl = "http://localhost:5173/reset-password?token=" + token + "&email=" + email;
    return ResponseEntity.ok(Map.of("resetUrl", resetUrl)); // Fuite du token secret
}
```

#### Impact théorique
N'importe quel attaquant peut soumettre l'adresse email d'un administrateur ou d'un utilisateur et intercepter immédiatement le lien et le jeton de réinitialisation dans la réponse HTTP pour s'emparer du compte sans jamais avoir accès à la boîte mail de la victime.

#### Remédiation défensive
Ne jamais renvoyer le jeton ni l'URL dans la réponse HTTP. Envoyer le lien par email via un service SMTP sécurisé et renvoyer une réponse générique neutre (*"Si cette adresse existe, un lien a été envoyé"*).

---

### VULN-16 : Divulgation d'informations via les traces d'erreurs détaillées (Verbose Error Handling)
* **Identifiant :** CWE-209 / OWASP A05:2021 – Security Misconfiguration
* **Criticité :** **MOYENNE** (CVSS v3.1 : 5.3)
* **Localisation :** [`backend/src/main/resources/application.properties`](file:///home/user/devfolio-audit/backend/src/main/resources/application.properties#L22-L25)

#### Explication technique
La configuration de Spring Boot force l'inclusion de la stacktrace et des messages détaillés sur toutes les erreurs HTTP :
```properties
server.error.include-stacktrace=always
server.error.include-message=always
server.error.include-binding-errors=always
```

#### Preuve (Vérification en direct)
Une simple requête vers une route inexistante ou générant une exception (comme `GET /` ou une erreur 500) renvoie la pile d'exécution Java complète avec les noms de classes, méthodes, numéros de lignes et versions des bibliothèques (`Tomcat 10.1.16`, `Spring Boot 3.2.0`, `Hibernate ORM`).

#### Remédiation défensive
Désactiver l'affichage des traces pour les clients en production :
```properties
server.error.include-stacktrace=never
server.error.include-message=never
```

---

### VULN-17 : Politique CORS permissive et protection CSRF désactivée
* **Identifiant :** CWE-942 / CWE-352 / OWASP A05:2021 – Security Misconfiguration
* **Criticité :** **MOYENNE** (CVSS v3.1 : 6.5)
* **Localisation :** [`backend/src/main/java/com/devfolio/config/SecurityConfig.java`](file:///home/user/devfolio-audit/backend/src/main/java/com/devfolio/config/SecurityConfig.java#L23-L31)

#### Explication technique
Spring Security est configuré pour accepter aveuglément toutes les origines, méthodes et en-têtes cross-origin (`*`) avec `csrf.disable()`.

#### Remédiation défensive
Restreindre la liste des origines CORS au seul domaine légitime de l'application (ex. `http://localhost`, ou domaine de production spécifique).

---

### VULN-18 : Absence de validation du token JWT par le backend & persistance des sessions expirées
* **Identifiant :** CWE-287 / CWE-613 / OWASP A07:2021 – Identification & Authentication Failures
* **Criticité :** **CRITIQUE** (CVSS v3.1 : 9.1)
* **Localisation :** [`backend/src/main/java/com/devfolio/config/SecurityConfig.java`](file:///home/user/devfolio-audit/backend/src/main/java/com/devfolio/config/SecurityConfig.java), architecture globale Spring Security

#### Explication technique
Bien que le client frontend injecte l'en-tête standard `Authorization: Bearer <token>` sur chaque appel HTTP via Axios, l'architecture backend ne possède aucun filtre de sécurité (`OncePerRequestFilter` / `JwtAuthenticationFilter`) pour intercepter cette requête, extraire le token, vérifier sa signature cryptographique et contrôler sa date d'expiration (`exp`).

Par conséquent :
1. **Tolérance aux tokens expirés :** Même si la durée de validité du token est dépassée, le backend ne le rejette pas car il ne le lit tout simplement pas.
2. **Absence de déconnexion automatique :** L'utilisateur continue de naviguer et d'effectuer des opérations sensibles avec un token pourtant périmé. Le serveur ne renvoie jamais de code HTTP `401 Unauthorized`.
3. **Absence de contexte de sécurité :** Le contexte de sécurité Spring (`SecurityContextHolder`) reste anonyme pour toutes les requêtes.

#### Remédiation défensive
1. Développer un filtre `JwtAuthenticationFilter` étendant `OncePerRequestFilter` qui extrait le token du header `Authorization`.
2. Valider le token avec `JwtService.validateToken(token)` : si le token est expiré (`ExpiredJwtException`) ou invalide, renvoyer immédiatement une réponse `401 Unauthorized` pour forcer la déconnexion côté frontend.
3. Si le token est valide, construire un `UsernamePasswordAuthenticationToken` et l'enregistrer dans `SecurityContextHolder.getContext().setAuthentication(...)`.
4. Enregistrer ce filtre dans `SecurityConfig.java` avant `UsernamePasswordAuthenticationFilter.class`.

---

## 3. Matrice de Priorisation des Remédiations

| Priorité | Vulnérabilité                                         |    Effort estimé     | Impact si non corrigé                                 |
| :------: | ----------------------------------------------------- | :------------------: | ----------------------------------------------------- |
|  **P1**  | **VULN-01 (Injection SQL)**                           |     Faible (1h)      | Fuite totale de la base de données                    |
|  **P1**  | **VULN-02 (Contrôle d'accès désactivé)**              |     Faible (2h)      | Prise de contrôle de l'API                            |
|  **P1**  | **VULN-03 (Bypass signature JWT)**                    |     Faible (1h)      | Usurpation d'identité administrateur                  |
|  **P1**  | **VULN-18 (Absence validation JWT & tokens expirés)** |      Moyen (2h)      | Sessions actives indéfiniment, absence de déconnexion |
|  **P1**  | **VULN-04 (Exposition Spring Actuator)**              | Très faible (15 min) | Fuite mémoire et extinction à distance                |
|  **P2**  | **VULN-05 (SSRF sur Avatar et Import)**               |      Moyen (3h)      | Pivot réseau interne / cloud metadata                 |
|  **P2**  | **VULN-06 (IDOR & Mass Assignment)**                  |      Moyen (3h)      | Altération de données et élévation de privilèges      |
|  **P2**  | **VULN-07 (Stored XSS sur Bio)**                      | Très faible (30 min) | Vol de sessions utilisateur                           |
|  **P2**  | **VULN-08 (Hachage MD5)**                             |      Moyen (2h)      | Révélation des mots de passe réels                    |
|  **P2**  | **VULN-12 (Absence d'unicité email / Account DoS)**   |   Faible (45 min)    | Blocage d'authentification et crash 500               |
|  **P2**  | **VULN-14 (DOM XSS sur paramètre ?ref=)**             | Très faible (15 min) | Exécution de code côté client                         |
|  **P2**  | **VULN-15 (Fuite du token de réinitialisation)**      |   Faible (30 min)    | Prise de contrôle de n'importe quel compte            |
|  **P3**  | **VULN-09 (Logs & Log4Shell)**                        |     Faible (1h)      | Fuite d'identifiants et risque RCE                    |
|  **P3**  | **VULN-13 (Énumération d'utilisateurs)**              | Très faible (15 min) | Moissonnage de comptes et ciblage d'attaques          |
|  **P3**  | **VULN-16 (Stacktraces détaillées)**                  | Très faible (10 min) | Divulgation de versions et composants                 |
|  **P3**  | **VULN-17 (CORS permissif / CSRF)**                   |   Faible (30 min)    | Requêtes cross-origin non sollicitées                 |
|  **P3**  | **VULN-10 & 11 (Secrets .env & JDWP)**                |     Faible (1h)      | Compromission d'infrastructure                        |



