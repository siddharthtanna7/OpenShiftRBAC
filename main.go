package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"sort"
	"strings"
	"time"
	"flag"

	"gopkg.in/yaml.v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	openshiftclientset "github.com/openshift/client-go/user/clientset/versioned"
)

// Structs for YAML configuration
type PermissionsConfig struct {
	SensitivePermissions []Permission `yaml:"sensitivePermissions"`
}

type Permission struct {
	Name       string   `yaml:"name"`
	Resources  []string `yaml:"resources"`
	Verbs      []string `yaml:"verbs"`
	Impact     string   `yaml:"impact"`
	APIGroups  []string `yaml:"apiGroups"`
	Exceptions struct {
		Users           []string `yaml:"users"`
		ServiceAccounts []string `yaml:"serviceAccounts"`
		Groups          []string `yaml:"groups"`
	} `yaml:"exceptions"`
}

// Identity represents a user, group, or service account
type Identity struct {
	Name        string
	Type        string // "user", "serviceAccount", or "group"
	Namespace   string
	Permissions []IdentityPermission
	Scope       string // "cluster-wide" or "namespace"
}

type IdentityPermission struct {
	Resources []string
	Verbs     []string
	APIGroups []string
}

type Violation struct {
	Identity Identity
	Rule     string
	Scope    string
	Impact   string
}

// Add this struct to consolidate violations
type ConsolidatedViolation struct {
    Identity    string
    Type        string
    Namespace   string
    Scope       string
    Violations  []string
    Impact      map[string]string
}

// Add these global variables
var (
	checkUsers          bool
	checkGroups         bool
	checkServiceAccounts bool
	checkAll            bool
)

func init() {
	// Define flags
	flag.BoolVar(&checkUsers, "users", false, "Check user identities")
	flag.BoolVar(&checkGroups, "groups", false, "Check group identities")
	flag.BoolVar(&checkServiceAccounts, "sa", false, "Check service account identities")
	flag.BoolVar(&checkAll, "all", false, "Check all identity types")
}

// Add this function to detect cluster type
func isOpenShiftCluster(clientset *kubernetes.Clientset) bool {
	_, err := clientset.RESTClient().Get().AbsPath("/apis/user.openshift.io").DoRaw(context.Background())
	return err == nil
}

func main() {
	// Parse flags
	flag.Parse()

	// If no specific type is selected, default to all
	if !checkUsers && !checkGroups && !checkServiceAccounts && !checkAll {
		checkAll = true
	}

	// Load configuration
	config, err := LoadConfig("permissions-config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Load kubeconfig
	kubeConfig, err := clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
	if err != nil {
		log.Fatalf("Failed to load kubeconfig: %v", err)
	}

	// Initialize Kubernetes client
	k8sClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		log.Fatalf("Failed to initialize Kubernetes client: %v", err)
	}

	// Try to initialize OpenShift client, but don't fail if it doesn't work
	ocClient, err := openshiftclientset.NewForConfig(kubeConfig)
	if err != nil {
		log.Printf("Note: OpenShift client initialization failed, will only check Kubernetes resources")
		ocClient = nil
	}

	// Get identities and check permissions
	identities, err := GetClusterIdentities(k8sClient, ocClient)
	if err != nil {
		log.Fatalf("Failed to get cluster identities: %v", err)
	}

	// Filter identities based on flags
	var filteredIdentities []Identity
	for _, identity := range identities {
		if shouldIncludeIdentity(identity) {
			filteredIdentities = append(filteredIdentities, identity)
		}
	}

	// Check permissions and collect violations
	var violations []Violation
	for _, identity := range filteredIdentities {
		identityViolations := CheckIdentityPermissions(config, identity)
		violations = append(violations, identityViolations...)
	}

	// Output results
	OutputViolations(violations)
}

func LoadConfig(filePath string) (*PermissionsConfig, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}

	var config PermissionsConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("error parsing config file: %v", err)
	}

	return &config, nil
}

func GetClusterIdentities(k8sClient *kubernetes.Clientset, ocClient *openshiftclientset.Clientset) ([]Identity, error) {
	var identities []Identity
	ctx := context.Background()
	
	// Detect if we're running on OpenShift
	isOpenShift := isOpenShiftCluster(k8sClient)
	
	// Get Users and Groups only if we're on OpenShift
	if isOpenShift && ocClient != nil {
		// Get OpenShift Users
		users, err := ocClient.UserV1().Users().List(ctx, metav1.ListOptions{})
		if err != nil {
			log.Printf("Warning: Could not fetch OpenShift users: %v", err)
		} else {
			for _, user := range users.Items {
				identity := Identity{
					Name:      user.Name,
					Type:      "user",
					Namespace: "",
					Scope:     "cluster-wide",
				}
				
				perms, err := getIdentityPermissions(k8sClient, identity)
				if err != nil {
					log.Printf("Warning: Could not fetch permissions for user %s: %v", user.Name, err)
					continue
				}
				identity.Permissions = perms
				identities = append(identities, identity)
			}
		}

		// Get OpenShift Groups
		groups, err := ocClient.UserV1().Groups().List(ctx, metav1.ListOptions{})
		if err != nil {
			log.Printf("Warning: Could not fetch OpenShift groups: %v", err)
		} else {
			for _, group := range groups.Items {
				identity := Identity{
					Name:      group.Name,
					Type:      "group",
					Namespace: "",
					Scope:     "cluster-wide",
				}
				
				perms, err := getIdentityPermissions(k8sClient, identity)
				if err != nil {
					log.Printf("Warning: Could not fetch permissions for group %s: %v", group.Name, err)
					continue
				}
				identity.Permissions = perms
				identities = append(identities, identity)
			}
		}
	}

	// Get Service Accounts (works on both Kubernetes and OpenShift)
	sas, err := k8sClient.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing service accounts: %v", err)
	}
	
	for _, sa := range sas.Items {
			identity := Identity{
				Name:      sa.Name,
				Type:      "serviceAccount",
				Namespace: sa.Namespace,
				Scope:     "namespace",
			}
			
			perms, err := getIdentityPermissions(k8sClient, identity)
			if err != nil {
				log.Printf("Warning: Could not fetch permissions for service account %s: %v", sa.Name, err)
				continue
			}
			identity.Permissions = perms
			identities = append(identities, identity)
	}
	
	return identities, nil
}

func getIdentityPermissions(clientset *kubernetes.Clientset, identity Identity) ([]IdentityPermission, error) {
	var permissions []IdentityPermission
	
	// Get role bindings for the identity
	roleBindings, err := clientset.RbacV1().RoleBindings(identity.Namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing role bindings: %v", err)
	}
	
	// Get cluster role bindings
	clusterRoleBindings, err := clientset.RbacV1().ClusterRoleBindings().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing cluster role bindings: %v", err)
	}
	
	// Process role bindings
	for _, rb := range roleBindings.Items {
		if isIdentityInBinding(identity, rb.Subjects) {
			perms, err := getRolePermissions(clientset, rb.RoleRef)
			if err != nil {
				return nil, err
			}
			permissions = append(permissions, perms...)
		}
	}
	
	// Process cluster role bindings
	for _, crb := range clusterRoleBindings.Items {
		if isIdentityInBinding(identity, crb.Subjects) {
			perms, err := getRolePermissions(clientset, crb.RoleRef)
			if err != nil {
				return nil, err
			}
			permissions = append(permissions, perms...)
		}
	}
	
	return permissions, nil
}

func CheckIdentityPermissions(config *PermissionsConfig, identity Identity) []Violation {
	var violations []Violation
	
	for _, sensitivePermission := range config.SensitivePermissions {
		// Skip if identity is in exceptions
		if isException(sensitivePermission, identity) {
			continue
		}
		
		// Check if identity has any of the sensitive permissions
		if hasMatchingPermissions(identity.Permissions, sensitivePermission) {
			violations = append(violations, Violation{
				Identity: identity,
				Rule:     sensitivePermission.Name,
				Scope:    identity.Scope,
				Impact:   sensitivePermission.Impact,
			})
		}
	}
	
	return violations
}

func isException(permission Permission, identity Identity) bool {
	switch identity.Type {
	case "user":
		for _, user := range permission.Exceptions.Users {
			if user == identity.Name {
				return true
			}
		}
	case "serviceAccount":
		for _, sa := range permission.Exceptions.ServiceAccounts {
			if fmt.Sprintf("%s:%s", identity.Namespace, identity.Name) == sa {
				return true
			}
		}
	case "group":
		for _, group := range permission.Exceptions.Groups {
			if group == identity.Name {
				return true
			}
		}
	}
	return false
}

func hasMatchingPermissions(identityPerms []IdentityPermission, sensitivePermission Permission) bool {
	for _, identityPerm := range identityPerms {
		// Check if there's any overlap in resources, verbs, and API groups
		if hasOverlap(identityPerm.Resources, sensitivePermission.Resources) &&
		   hasOverlap(identityPerm.Verbs, sensitivePermission.Verbs) &&
		   hasOverlap(identityPerm.APIGroups, sensitivePermission.APIGroups) {
			return true
		}
	}
	return false
}

func hasOverlap(a, b []string) bool {
	for _, itemA := range a {
		for _, itemB := range b {
			if itemA == itemB || itemA == "*" {
				return true
			}
		}
	}
	return false
}

func OutputViolations(violations []Violation) {
	// Map to store consolidated violations
	consolidated := make(map[string]*ConsolidatedViolation)
	
	// Consolidate violations by identity
	for _, v := range violations {
		key := v.Identity.Name
		if _, exists := consolidated[key]; !exists {
			consolidated[key] = &ConsolidatedViolation{
				Identity:   v.Identity.Name,
				Type:      v.Identity.Type,
				Namespace: v.Identity.Namespace,
				Scope:     v.Identity.Scope,
				Violations: []string{},
					Impact:    make(map[string]string),
			}
		}
		consolidated[key].Violations = append(consolidated[key].Violations, v.Rule)
		consolidated[key].Impact[v.Rule] = v.Impact
	}

	// Output formatted report
	fmt.Println("\n=== Security Policy Violation Report ===")
	fmt.Printf("Generated: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println("=======================================\n")

	// Group by identity type
	printIdentityViolations("Service Accounts", consolidated, "serviceAccount")
	printIdentityViolations("Users", consolidated, "user")
	printIdentityViolations("Groups", consolidated, "group")
	
	// Print summary
	printSummary(consolidated)
}

func printIdentityViolations(title string, consolidated map[string]*ConsolidatedViolation, identityType string) {
	fmt.Printf("\n%s\n%s\n", title, strings.Repeat("-", len(title)))
	
	found := false
	for identity, cv := range consolidated {
		if cv.Type != identityType {
			continue
		}
		found = true
		
		fmt.Printf("\n🔴 Identity: %s\n", identity)
		if cv.Namespace != "" {
			fmt.Printf("   Namespace: %s\n", cv.Namespace)
		}
		fmt.Printf("   Scope: %s\n", cv.Scope)
		
		fmt.Println("   Policy Violations:")
		for i, violation := range cv.Violations {
			fmt.Printf("   %d. %s\n", i+1, violation)
			fmt.Printf("      Impact: %s\n", cv.Impact[violation])
		}
		
		fmt.Printf("   Total Violations: %d\n", len(cv.Violations))
	}
	
	if !found {
		fmt.Println("No violations found.")
	}
}

func printSummary(consolidated map[string]*ConsolidatedViolation) {
	fmt.Println("\n=== Summary ===")
	
	// Count violations by type
	var totalViolations, totalIdentities int
	typeCount := make(map[string]int)
	violationCount := make(map[string]int)
	
	for _, cv := range consolidated {
		totalIdentities++
		typeCount[cv.Type]++
		totalViolations += len(cv.Violations)
		
		for _, v := range cv.Violations {
			violationCount[v]++
		}
	}
	
	// Print statistics
	fmt.Printf("\nViolation Statistics:\n")
	fmt.Printf("Total Identities with Violations: %d\n", totalIdentities)
	fmt.Printf("Total Policy Violations: %d\n\n", totalViolations)
	
	fmt.Println("Violations by Identity Type:")
	for iType, count := range typeCount {
		fmt.Printf("- %s: %d\n", iType, count)
	}
	
	fmt.Println("\nMost Common Policy Violations:")
	// Sort violations by frequency
	type violationFreq struct {
		name  string
		count int
	}
	var sorted []violationFreq
	for name, count := range violationCount {
		sorted = append(sorted, violationFreq{name, count})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})
	
	for _, v := range sorted {
		fmt.Printf("- %s: %d occurrences\n", v.name, v.count)
	}
}

func getRolePermissions(clientset *kubernetes.Clientset, roleRef rbacv1.RoleRef) ([]IdentityPermission, error) {
	var permissions []IdentityPermission
	ctx := context.Background()

	switch roleRef.Kind {
	case "ClusterRole":
		role, err := clientset.RbacV1().ClusterRoles().Get(ctx, roleRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("error getting cluster role %s: %v", roleRef.Name, err)
		}
		
		for _, rule := range role.Rules {
			permissions = append(permissions, IdentityPermission{
				Resources: rule.Resources,
				Verbs:     rule.Verbs,
				APIGroups: rule.APIGroups,
			})
		}

	case "Role":
		// For regular roles, we need to get the role from the correct namespace
		// This would need to be passed in from the calling context
		// For now, we'll use the default namespace as an example
		role, err := clientset.RbacV1().Roles("default").Get(ctx, roleRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("error getting role %s: %v", roleRef.Name, err)
		}
		
		for _, rule := range role.Rules {
			permissions = append(permissions, IdentityPermission{
				Resources: rule.Resources,
				Verbs:     rule.Verbs,
				APIGroups: rule.APIGroups,
			})
		}
	}

	return permissions, nil
}

func isIdentityInBinding(identity Identity, subjects []rbacv1.Subject) bool {
	for _, subject := range subjects {
		switch identity.Type {
		case "user":
			if subject.Kind == "User" && subject.Name == identity.Name {
				return true
			}
		case "serviceAccount":
			if subject.Kind == "ServiceAccount" && 
			   subject.Name == identity.Name && 
			   subject.Namespace == identity.Namespace {
				return true
			}
		case "group":
			if subject.Kind == "Group" && subject.Name == identity.Name {
				return true
			}
		}
	}
	return false
}

// Add this helper function
func shouldIncludeIdentity(identity Identity) bool {
	if checkAll {
		return true
	}

	switch identity.Type {
	case "user":
		return checkUsers
	case "group":
		return checkGroups
	case "serviceAccount":
		return checkServiceAccounts
	default:
		return false
	}
}
