# Mémo de Formation : Principes Fondamentaux de Sécurité des API REST

**Objectif de formation :** Ce mémo synthétise les bonnes pratiques et standards de sécurité indispensables pour concevoir, développer et auditer des API REST modernes et robustes.  
**Public cible :** Développeurs backend/frontend, auditeurs de sécurité, administrateurs système.  
**Référentiels de référence :** OWASP API Security Top 10, NIST SP 800-63, RFC 7519 (JWT), RFC 6749 (OAuth 2.0).

---

## Sommaire
1. [Section 1 : Authentification (Qui est l'utilisateur ?)](#section-1--authentification)
2. [Section 2 : Gestion des rôles et contrôle d'accès (Que peut faire l'utilisateur ?)](#section-2--gestion-des-rôles-et-contrôle-daccès)
3. [Section 3 : Validation et assainissement des données (Que transmet l'utilisateur ?)](#section-3--validation-et-assainissement-des-données)
4. [Checklist récapitulative de conformité](#checklist-récapitulative-pour-le-développeur)

---

## Section 1 : Authentification

L'authentification a pour but de vérifier l'identité déclarée par un client (utilisateur ou machine) de manière fiable et infalsifiable.

### 1.1. Stockage sécurisé des mots de passe
* **Règle absolue :** Ne **jamais** stocker de mot de passe en clair ni utiliser d'algorithmes de hachage rapides ou obsolètes (MD5, SHA-1, SHA-256 seul).
* **Fonctions adaptatives obligatoires :** Utiliser des fonctions de dérivation de clé résistantes aux attaques matérielles (GPU/ASIC) avec salage cryptographique (*salt*) automatique :
  * **Argon2id** (recommandation n°1 actuelle de l'OWASP).
  * **BCrypt** (avec un facteur de coût minimum de 12).
  * **PBKDF2** (avec SHA-256 et minimum 600 000 itérations).
* **Politique de saisie :**
  * Pas de troncature arbitraire du mot de passe.
  * Vérification de la robustesse (longueur minimale d'au moins 12 caractères).
  * Comparaison contre les dictionnaires de mots de passe compromis connus (HIBP).

### 1.2. Gestion des jetons d'accès (JSON Web Tokens - JWT)
Le JWT est le standard de facto pour les API stateless :
* **Signature cryptographique obligatoire :**
  * Si algorithme symétrique (ex. `HS256`) : la clé secrète doit être aléatoire et respecter une taille minimale stricte de **256 bits (32 octets)**.
  * Si algorithme asymétrique (ex. `RS256` ou `ES256`) : signature avec clé privée et vérification avec clé publique.
  * **Interdiction stricte de l'algorithme "none" :** Le validateur du serveur doit rejeter formellement tout jeton dépourvu de signature ou ayant un header `alg: "none"`.
* **Durée de validité (*Expiration / TTL*) et Déconnexion :**
  * Tout jeton doit posséder une revendication d'expiration (`exp`) courte (ex. 15 à 60 minutes).
  * Le backend doit **intercepter chaque requête entrante** (via un filtre de sécurité / middleware) pour valider cryptographiquement la signature et vérifier que l'heure courante ne dépasse pas la date d'expiration (`exp`).
  * Si le token est expiré, altéré ou absent, le serveur doit **immédiatement rejeter la requête avec un statut HTTP 401 Unauthorized**.
  * Côté client, la réception d'un statut 401 doit forcer la déconnexion immédiate (suppression du token local et redirection vers l'écran de connexion). Ne jamais laisser le client décider seul si une session est active.
  * Utiliser un mécanisme de jeton de rafraîchissement (*Refresh Token*) stocké côté serveur avec possibilité de révocation pour renouveler les accès en toute sécurité.
* **Intégrité des Claims :**
  * Ne jamais inclure de données hautement sensibles en clair dans le payload d'un JWT (les claims sont uniquement encodés en Base64Url, ils ne sont pas chiffrés).

### 1.3. Stockage et transport des identifiants
* **Chiffrement en transit :** Exiger exclusivement **HTTPS / TLS 1.3** pour toute communication avec l'API. Aucun identifiant ne doit transiter en clair sur le réseau.
* **Stockage côté client (Navigateur Web) :**
  * Privilégier les cookies avec les drapeaux :
    * `HttpOnly` : Empêche l'accès au cookie via JavaScript (neutralise le vol de session en cas de faille XSS).
    * `Secure` : Force la transmission uniquement via des connexions chiffrées HTTPS.
    * `SameSite=Strict` ou `Lax` : Protège contre les attaques de type Cross-Site Request Forgery (CSRF).
  * *Éviter le `localStorage`* pour stocker des jetons sensibles car il est lisible par n'importe quel script JavaScript exécuté sur la page.

---

## Section 2 : Gestion des rôles et contrôle d'accès

L'autorisation intervient après l'authentification et garantit qu'un utilisateur n'accède qu'aux seules fonctionnalités et données pour lesquelles il a reçu une permission explicite.

### 2.1. Principes d'architecture
* **Moindre Privilège (*Least Privilege*) :** Par défaut, un utilisateur (ou service) ne doit disposer d'aucun droit hormis ceux strictement nécessaires à sa fonction.
* **Refus par défaut (*Deny by Default*) :** Toute nouvelle route ou ressource de l'API doit être fermée à l'accès public, sauf mention explicite de mise en accès libre.
* **Never Trust the Client (Ne jamais faire confiance au client) :**
  * Un contrôle d'accès côté frontend (ex. masquer un bouton ou vérifier `localStorage.getItem("role")`) n'a qu'une valeur ergonomique.
  * **Chaque requête HTTP arrivant sur le backend doit être contrôlée de manière autonome et indépendante.**

### 2.2. Modèles de contrôle d'accès
* **RBAC (Role-Based Access Control) :**
  * Attribution de rôles (ex. `ROLE_USER`, `ROLE_ADMIN`).
  * Sécurisation globale au niveau des points de terminaison HTTP :
    ```java
    // Exemple Spring Security
    .requestMatchers("/api/admin/**").hasRole("ADMIN")
    .requestMatchers("/api/projects/**").authenticated()
    ```
* **Contrôle au niveau méthode (*Method Security*) :**
  * Utilisation d'annotations pour verrouiller l'exécution des fonctions métier :
    ```java
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteSystemResource(...)
    ```

### 2.3. Prévention des failles majeures d'autorisation
* **BOLA / IDOR (Broken Object Level Authorization - Faille n°1 OWASP API) :**
  * Ne jamais se fier uniquement à l'identifiant fourni dans l'URL (`/api/projects/{id}`).
  * Le backend doit toujours vérifier que l'utilisateur authentifié est le **propriétaire légitime** de l'objet manipulé avant d'autoriser une lecture, modification ou suppression :
    ```java
    Project project = projectRepository.findById(id).orElseThrow();
    if (!project.getOwnerId().equals(authenticatedUser.getId()) && !authenticatedUser.isAdmin()) {
        throw new AccessDeniedException("Accès non autorisé à cette ressource.");
    }
    ```
* **Prévention du Mass Assignment (Affectation de masse) :**
  * Ne jamais binder directement une entité de base de données à une requête entrante (`@RequestBody User user`).
  * Utiliser obligatoirement des **DTOs (Data Transfer Objects)** restreints pour filtrer les champs modifiables par l'utilisateur (empêcher qu'un utilisateur ne s'injecte `"role": "ADMIN"` ou modifie son propre quota).

---

## Section 3 : Validation et assainissement des données

Tout flux de données provenant de l'extérieur (URL, paramètres de requête, corps JSON, en-têtes HTTP) doit être considéré comme potentiellement hostile tant qu'il n'a pas été validé.

### 3.1. Stratégie de validation : Liste blanche (*Allow-list*)
* **Approche positive :** Définir strictement ce qui est autorisé (types, longueurs, formats attendus, expressions régulières) plutôt que d'essayer de filtrer ce qui est interdit (les listes noires sont toujours contournables).
* **Validation déclarative (ex. Bean Validation / Jakarta Validation) :**
  * Appliquer des contraintes strictes sur chaque champ des DTOs :
    ```java
    public class UpdateProfileRequest {
        @NotNull
        @Email(message = "Format d'email invalide")
        @Size(max = 255)
        private String email;

        @Size(max = 1000, message = "La bio ne peut excéder 1000 caractères")
        private String bio;
    }
    ```
  * Valider systématiquement à l'entrée du contrôleur avec `@Valid`.

### 3.2. Prévention des injections
* **Injections SQL (SQLi) :**
  * Proscrire formellement la concaténation de chaînes dans la construction de requêtes SQL.
  * Utiliser obligatoirement des requêtes préparées avec paramètres nommés (*Prepared Statements*) ou les méthodes abstraites de frameworks ORM (JPA/Hibernate) :
    ```java
    // Correct : Le paramètre :query est échappé par le driver
    @Query("SELECT p FROM Project p WHERE p.title LIKE %:query% AND p.isPublic = true")
    List<Project> searchProjects(@Param("query") String query);
    ```
* **Injections de requêtes côté serveur (SSRF - Server-Side Request Forgery) :**
  * Si l'API doit télécharger une ressource distante depuis une URL fournie par l'utilisateur :
    1. Valider le protocole (autoriser uniquement `https://`).
    2. Valider le nom de domaine via une liste blanche stricte.
    3. Résoudre l'adresse IP et bloquer immédiatement les adresses locales et privées (`127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, et les adresses de métadonnées cloud `169.254.169.254`).
* **Cross-Site Scripting (XSS) :**
  * Échapper contextuellement les données avant tout affichage.
  * Côté frontend, ne jamais utiliser d'injection HTML brute (`v-html` en Vue.js ou `dangerouslySetInnerHTML` en React) sans assainissement préalable par une bibliothèque certifiée (ex. DOMPurify).

### 3.3. Gestion des erreurs et limitation de débit
* **Messages d'erreur neutres et génériques :**
  * Ne jamais renvoyer de stacktraces ou de détails internes du framework (`server.error.include-stacktrace=never`).
  * Empêcher l'**énumération d'utilisateurs** en unifiant les messages d'échec de connexion (*"Identifiants invalides"* au lieu de distinguer utilisateur inconnu et mot de passe faux).
* **Limitation de débit (*Rate Limiting*) :**
  * Protéger les points d'entrée sensibles (connexion, inscription, réinitialisation de mot de passe, recherche) contre les attaques par force brute et par déni de service (DoS) en limitant le nombre de requêtes autorisées par IP ou par utilisateur sur un intervalle de temps donné.

---

## Checklist Récapitulative pour le Développeur

| Domaine | Critère de vérification | Statut |
|---|---|:---:|
| **Authentification** | Les mots de passe sont hachés avec Argon2id ou BCrypt (coût >= 12). | [ ] |
| **Authentification** | Les JWT sont signés avec un secret d'au moins 256 bits et ont une durée de vie limitée (`exp`). | [ ] |
| **Authentification** | Le validateur JWT rejette formellement les tokens non signés (pas de fallback "none"). | [ ] |
| **Authentification** | Les messages d'échec de connexion sont génériques (anti-énumération). | [ ] |
| **Rôles & Accès** | La politique de sécurité applique le principe de refus par défaut (*Deny by Default*). | [ ] |
| **Rôles & Accès** | Chaque modification/suppression de ressource valide la propriété de l'objet (anti-BOLA/IDOR). | [ ] |
| **Rôles & Accès** | Les entités sont découplées des requêtes via des DTOs stricts (anti-Mass Assignment). | [ ] |
| **Validation** | Toutes les requêtes entrantes sont validées sur une liste blanche (taille, type, format). | [ ] |
| **Validation** | Toutes les requêtes en base utilisent des paramètres préparés (anti-SQLi). | [ ] |
| **Validation** | Aucun appel réseau sortant ne peut joindre le réseau interne ou `localhost` (anti-SSRF). | [ ] |
| **Configuration** | Les endpoints de debug/management (ex. Actuator) sont désactivés ou strictement protégés. | [ ] |
| **Configuration** | L'affichage des stacktraces en production est désactivé (`include-stacktrace=never`). | [ ] |
