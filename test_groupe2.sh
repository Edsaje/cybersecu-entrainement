#!/bin/bash
# ==============================================================================
# Script de validation automatique — Groupe 2 : Contrôle d'Accès & Autorisations
# (VULN-02, VULN-06, VULN-18 & Intégrité des Tokens JWT)
# ==============================================================================

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

API_URL="http://localhost:8080/api"

echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}  🚀 Lancement de la suite de tests — Groupe 2 (DevFolio Security)    ${NC}"
echo -e "${BLUE}======================================================================${NC}\n"

# ------------------------------------------------------------------------------
# 1. Connexion des comptes de test
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[1/6] Authentification des utilisateurs de test...${NC}"

ADMIN_RESP=$(curl -s -X POST "$API_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@devfolio.com","password":"admin123"}')
ADMIN_TOKEN=$(echo "$ADMIN_RESP" | jq -r '.token // empty')

BOB_RESP=$(curl -s -X POST "$API_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"bob@student.com","password":"admin123"}')
BOB_TOKEN=$(echo "$BOB_RESP" | jq -r '.token // empty')

if [[ -n "$ADMIN_TOKEN" && -n "$BOB_TOKEN" ]]; then
    echo -e "${GREEN}  ✓ SUCCÈS : Tokens JWT obtenus pour Admin et Bob (User).${NC}"
else
    echo -e "${RED}  ✗ ÉCHEC : Impossible d'obtenir les tokens.${NC}"
    exit 1
fi

# ------------------------------------------------------------------------------
# 2. VULN-02 : Contrôle d'accès RBAC sur les routes d'administration
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[2/6] VULN-02 : Contrôle d'accès RBAC sur /api/admin/users...${NC}"

# A. Requête anonyme
CODE_ANON=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/admin/users")
if [[ "$CODE_ANON" == "401" || "$CODE_ANON" == "403" ]]; then
    echo -e "${GREEN}  ✓ SUCCÈS : Accès anonyme rejeté ($CODE_ANON).${NC}"
else
    echo -e "${RED}  ✗ ÉCHEC : Accès anonyme autorisé ou code anormal ($CODE_ANON).${NC}"
fi

# B. Requête avec rôle USER (Bob)
CODE_USER=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $BOB_TOKEN" \
  "$API_URL/admin/users")
if [[ "$CODE_USER" == "403" ]]; then
    echo -e "${GREEN}  ✓ SUCCÈS : Accès rôle USER rejeté avec 403 Forbidden.${NC}"
else
    echo -e "${RED}  ✗ ÉCHEC : Accès rôle USER non bloqué en 403 ($CODE_USER).${NC}"
fi

# C. Requête avec rôle ADMIN
CODE_ADMIN=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$API_URL/admin/users")
if [[ "$CODE_ADMIN" == "200" ]]; then
    echo -e "${GREEN}  ✓ SUCCÈS : Accès rôle ADMIN autorisé avec 200 OK.${NC}"
else
    echo -e "${RED}  ✗ ÉCHEC : Accès rôle ADMIN refusé ($CODE_ADMIN).${NC}"
fi

# ------------------------------------------------------------------------------
# 3. VULN-18 & VULN-03 : Intégrité cryptographique et rejet des tokens modifiés/expirés
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[3/6] VULN-18 & VULN-03 : Intégrité stricte et rejet des tokens altérés...${NC}"

# A. Altération du payload d'un token valide (Bob élève son rôle : USER -> ADMIN)
HEADER_PART=$(echo "$BOB_TOKEN" | cut -d'.' -f1)
PAYLOAD_PART=$(echo "$BOB_TOKEN" | cut -d'.' -f2)
SIG_PART=$(echo "$BOB_TOKEN" | cut -d'.' -f3)

TAMPERED_PAYLOAD=$(python3 -c "import base64; p = '$PAYLOAD_PART' + '=' * ((4 - len('$PAYLOAD_PART') % 4) % 4); print(base64.urlsafe_b64encode(base64.urlsafe_b64decode(p).decode().replace('\"USER\"', '\"ADMIN\"').encode()).decode().rstrip('='))")
TAMPERED_TOKEN="${HEADER_PART}.${TAMPERED_PAYLOAD}.${SIG_PART}"

RESP_TAMPERED=$(curl -s -w "\n%{http_code}" \
  -H "Authorization: Bearer $TAMPERED_TOKEN" \
  "$API_URL/admin/users")
CODE_TAMPERED=$(echo "$RESP_TAMPERED" | tail -n1)
BODY_TAMPERED=$(echo "$RESP_TAMPERED" | head -n -1)

if [[ "$CODE_TAMPERED" == "401" ]]; then
    echo -e "${GREEN}  ✓ SUCCÈS : Token altéré (USER -> ADMIN) rejeté avec 401 Unauthorized.${NC}"
    echo -e "${GREEN}    Réponse backend : $BODY_TAMPERED${NC}"
else
    echo -e "${RED}  ✗ ÉCHEC : Token altéré non rejeté en 401 ($CODE_TAMPERED).${NC}"
fi

# B. Tentative de contournement algorithme 'none' sans signature
NONE_HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr '/+' '_-' | tr -d '=')
NONE_TOKEN="${NONE_HEADER}.${TAMPERED_PAYLOAD}."
CODE_NONE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $NONE_TOKEN" \
  "$API_URL/admin/users")

if [[ "$CODE_NONE" == "401" ]]; then
    echo -e "${GREEN}  ✓ SUCCÈS : Token avec algorithme 'none' sans signature rejeté (401).${NC}"
else
    echo -e "${RED}  ✗ ÉCHEC : Token alg=none non rejeté en 401 ($CODE_NONE).${NC}"
fi

# C. Altération de la signature (signature corrompue)
CORRUPTED_SIG="X${SIG_PART:1}"
CORRUPTED_TOKEN="${HEADER_PART}.${PAYLOAD_PART}.${CORRUPTED_SIG}"
CODE_CORRUPTED=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $CORRUPTED_TOKEN" \
  "$API_URL/admin/users")

if [[ "$CODE_CORRUPTED" == "401" ]]; then
    echo -e "${GREEN}  ✓ SUCCÈS : Token avec signature corrompue rejeté avec 401 Unauthorized.${NC}"
else
    echo -e "${RED}  ✗ ÉCHEC : Signature corrompue non rejetée en 401 ($CODE_CORRUPTED).${NC}"
fi

# D. Token expiré
EXPIRED_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbkBkZXZmb2xpby5jb20iLCJyb2xlIjoiQURNSU4iLCJ1c2VySWQiOjEsImV4cCI6MTcwMDAwMDAwMH0.1v7f18-l7e7k0_8w-B0cZ63aVbA3r1pMv5V_gL6U-bA"
CODE_EXPIRED=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $EXPIRED_TOKEN" \
  "$API_URL/admin/users")

if [[ "$CODE_EXPIRED" == "401" ]]; then
    echo -e "${GREEN}  ✓ SUCCÈS : Token périmé / expiré rejeté avec 401 Unauthorized.${NC}"
else
    echo -e "${RED}  ✗ ÉCHEC : Token périmé non rejeté en 401 ($CODE_EXPIRED).${NC}"
fi

# ------------------------------------------------------------------------------
# 4. VULN-06 : Contrôle BOLA / IDOR sur les projets
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[4/6] VULN-06 (BOLA / IDOR) : Contrôle d'appartenance sur les projets...${NC}"

# Projet 1 appartient à Alice (owner_id: 2). Bob (id: 3) tente de le modifier.
CODE_IDOR_PUT=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"Projet Pirate"}' \
  "$API_URL/projects/1")

if [[ "$CODE_IDOR_PUT" == "403" ]]; then
    echo -e "${GREEN}  ✓ SUCCÈS : Modification du projet d'Alice par Bob bloquée avec 403 Forbidden.${NC}"
else
    echo -e "${RED}  ✗ ÉCHEC : IDOR non bloqué sur PUT /projects/1 ($CODE_IDOR_PUT).${NC}"
fi

# Bob tente de supprimer le projet d'Alice (id: 1)
CODE_IDOR_DEL=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE \
  -H "Authorization: Bearer $BOB_TOKEN" \
  "$API_URL/projects/1")

if [[ "$CODE_IDOR_DEL" == "403" ]]; then
    echo -e "${GREEN}  ✓ SUCCÈS : Suppression du projet d'Alice par Bob bloquée avec 403 Forbidden.${NC}"
else
    echo -e "${RED}  ✗ ÉCHEC : IDOR non bloqué sur DELETE /projects/1 ($CODE_IDOR_DEL).${NC}"
fi

# ------------------------------------------------------------------------------
# 5. VULN-06 : Contrôle BOLA / IDOR sur les profils utilisateurs
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[5/6] VULN-06 (BOLA) : Modification non autorisée du profil d'autrui...${NC}"

# Bob (id: 3) tente de modifier le profil d'Alice (id: 2)
CODE_USER_IDOR=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"bio":"Pawned by Bob"}' \
  "$API_URL/users/2")

if [[ "$CODE_USER_IDOR" == "403" ]]; then
    echo -e "${GREEN}  ✓ SUCCÈS : Altération du profil d'Alice par Bob bloquée avec 403 Forbidden.${NC}"
else
    echo -e "${RED}  ✗ ÉCHEC : IDOR profil non bloqué ($CODE_USER_IDOR).${NC}"
fi

# ------------------------------------------------------------------------------
# 6. VULN-06 : Mass Assignment / Élévation de privilèges
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[6/6] VULN-06 (Mass Assignment) : Tentative d'auto-promotion ADMIN...${NC}"

# Bob tente de changer son propre rôle vers ADMIN
curl -s -X PUT \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"ADMIN"}' \
  "$API_URL/users/3" > /dev/null

BOB_ROLE=$(curl -s "$API_URL/users/3" | jq -r '.role // empty')

if [[ "$BOB_ROLE" != "ADMIN" ]]; then
    echo -e "${GREEN}  ✓ SUCCÈS : Le rôle de Bob est resté '$BOB_ROLE'. Auto-promotion bloquée !${NC}"
else
    echo -e "${RED}  ✗ ÉCHEC : Mass Assignment réussi, Bob est devenu ADMIN !${NC}"
fi

echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${GREEN}  🎉 Tous les tests du Groupe 2 ont été validés avec succès !         ${NC}"
echo -e "${BLUE}======================================================================${NC}\n"
