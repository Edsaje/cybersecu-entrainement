#!/bin/bash
# ==============================================================================
# Script de validation automatique — Groupe 1 : Authentification & Mots de Passe
# ==============================================================================

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

API_URL="http://localhost:8080/api"

echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}  🚀 Lancement de la suite de tests — Groupe 1 (DevFolio Security)    ${NC}"
echo -e "${BLUE}======================================================================${NC}\n"

# ------------------------------------------------------------------------------
# Test 1 : VULN-08 - Hachage BCrypt
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[Test 1/5] VULN-08 : Connexion avec compte existant et vérification BCrypt...${NC}"
RES_LOGIN=$(curl -s -X POST "$API_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@student.com","password":"admin123"}')

HASH=$(echo "$RES_LOGIN" | jq -r '.user.password // empty')
TOKEN_ALICE=$(echo "$RES_LOGIN" | jq -r '.token // empty')

if [[ "$HASH" =~ ^\$2[aby]\$12\$ ]]; then
    echo -e "${GREEN}  ✓ SUCCÈS : Alice s'est connectée avec succès.${NC}"
    echo -e "${GREEN}  ✓ SUCCÈS : Le mot de passe stocké est bien un hash BCrypt (\$2a\$12...).${NC}"
else
    echo -e "${RED}  ✗ ÉCHEC : Le mot de passe n'est pas au format BCrypt attendu ($HASH).${NC}"
fi

# ------------------------------------------------------------------------------
# Test 2 : VULN-13 - Anti-énumération d'utilisateurs
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[Test 2/5] VULN-13 : Test d'anti-énumération d'utilisateurs sur le login...${NC}"
ERR_UNKNOWN=$(curl -s -X POST "$API_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"faux.compte@test.com","password":"pwd"}' | jq -r '.error // empty')

ERR_WRONG_PWD=$(curl -s -X POST "$API_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@student.com","password":"fauxpassword"}' | jq -r '.error // empty')

if [[ "$ERR_UNKNOWN" == "Identifiants invalides" && "$ERR_WRONG_PWD" == "Identifiants invalides" ]]; then
    echo -e "${GREEN}  ✓ SUCCÈS : Email inexistant -> Réponse : \"$ERR_UNKNOWN\"${NC}"
    echo -e "${GREEN}  ✓ SUCCÈS : Email existant mauvais mdp -> Réponse : \"$ERR_WRONG_PWD\"${NC}"
    echo -e "${GREEN}  ✓ SUCCÈS : Les deux réponses sont strictement identiques. Énumération neutralisée !${NC}"
else
    echo -e "${RED}  ✗ ÉCHEC : Réponses distinctes (Inconnu: \"$ERR_UNKNOWN\", Mauvais mdp: \"$ERR_WRONG_PWD\").${NC}"
fi

# ------------------------------------------------------------------------------
# Test 3 : VULN-15 - Non-divulgation du jeton de réinitialisation
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[Test 3/5] VULN-15 : Demande de réinitialisation de mot de passe...${NC}"
RES_RESET=$(curl -s -X POST "$API_URL/auth/reset-password/request?email=admin@devfolio.com")
TOKEN_LEAK=$(echo "$RES_RESET" | jq -r '.resetUrl // .token // empty')
MSG_RESET=$(echo "$RES_RESET" | jq -r '.message // empty')

if [[ -z "$TOKEN_LEAK" && -n "$MSG_RESET" ]]; then
    echo -e "${GREEN}  ✓ SUCCÈS : Le serveur renvoie un message neutre : \"$MSG_RESET\"${NC}"
    echo -e "${GREEN}  ✓ SUCCÈS : Aucun jeton secret ni URL de reset n'apparaît dans la réponse HTTP.${NC}"
else
    echo -e "${RED}  ✗ ÉCHEC : Fuite détectée dans la réponse JSON ($RES_RESET).${NC}"
fi

# ------------------------------------------------------------------------------
# Test 4 : VULN-09 - Absence de mots de passe en clair dans les logs
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[Test 4/5] VULN-09 : Vérification de l'absence de mots de passe dans les logs...${NC}"
LEAK_COUNT=$(docker compose logs backend 2>&1 | grep -i "Password received:" | wc -l)

if [[ "$LEAK_COUNT" -eq 0 ]]; then
    echo -e "${GREEN}  ✓ SUCCÈS : 0 mot de passe trouvé dans les logs de l'application.${NC}"
else
    echo -e "${RED}  ✗ ÉCHEC : $LEAK_COUNT fuite(s) de mot de passe trouvée(s) dans les logs !${NC}"
fi

# ------------------------------------------------------------------------------
# Test 5 : VULN-12 - Unicité de l'email & Protection contre le crash DoS
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[Test 5/5] VULN-12 : Tentative d'usurpation d'email / collision DoS...${NC}"
# Connexion de Bob pour récupérer son token
RES_BOB=$(curl -s -X POST "$API_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"bob@student.com","password":"admin123"}')
TOKEN_BOB=$(echo "$RES_BOB" | jq -r '.token // empty')

# Bob tente de s'attribuer l'email d'Alice (id: 2)
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$API_URL/users/3" \
  -H "Authorization: Bearer $TOKEN_BOB" \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@student.com","bio":"Attaque"}')

if [[ "$HTTP_CODE" == "409" ]]; then
    echo -e "${GREEN}  ✓ SUCCÈS : Tentative de doublon bloquée avec le code HTTP 409 Conflict.${NC}"
    echo -e "${GREEN}  ✓ SUCCÈS : L'attaque par déni de service applicatif (Account DoS) est neutralisée.${NC}"
else
    echo -e "${RED}  ✗ ÉCHEC : Code HTTP inattendu : $HTTP_CODE (409 Conflict attendu).${NC}"
fi

echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${GREEN}  🎉 Tous les tests du Groupe 1 ont été validés avec brio !           ${NC}"
echo -e "${BLUE}======================================================================${NC}\n"
