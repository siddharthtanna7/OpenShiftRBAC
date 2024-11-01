package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"time"
	"flag"

	"gopkg.in/yaml.v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	openshiftclientset "github.com/openshift/client-go/user/clientset/versioned"
	"github.com/schollz/progressbar/v3"
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

	fmt.Println("\n🚀 Starting permission audit...")
	
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

	fmt.Println("\n🔎 Analyzing permissions...")
	
	// Check permissions and collect violations
	var violations []Violation
	for _, identity := range filteredIdentities {
		identityViolations := CheckIdentityPermissions(config, identity)
		violations = append(violations, identityViolations...)
	}

	fmt.Println("\n📊 Generating report...")
	
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
	
	fmt.Println("\n🔍 Scanning cluster identities...")
	
	// Get Users and Groups only if we're on OpenShift
	if isOpenShift && ocClient != nil {
		// Get OpenShift Users
		users, err := ocClient.UserV1().Users().List(ctx, metav1.ListOptions{})
		if err != nil {
			log.Printf("Warning: Could not fetch OpenShift users: %v", err)
		} else {
			bar := progressbar.NewOptions(len(users.Items),
				progressbar.OptionSetDescription("Processing Users"),
				progressbar.OptionSetTheme(progressbar.Theme{
					Saucer:        "=",
					SaucerHead:    ">",
					SaucerPadding: " ",
					BarStart:      "[",
					BarEnd:        "]",
				}),
				progressbar.OptionSetWidth(40),
				progressbar.OptionClearOnFinish(),
				progressbar.OptionSetRenderBlankState(true),
				progressbar.OptionEnableColorCodes(true),
				progressbar.OptionShowCount(),
				progressbar.OptionSetPredictTime(false),
				progressbar.OptionFullWidth(),
			)
			
			for _, user := range users.Items {
				bar.Add(1)
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
			fmt.Println() // New line after progress bar
		}

		// Get OpenShift Groups
		groups, err := ocClient.UserV1().Groups().List(ctx, metav1.ListOptions{})
		if err != nil {
			log.Printf("Warning: Could not fetch OpenShift groups: %v", err)
		} else {
			bar := progressbar.NewOptions(len(groups.Items),
				progressbar.OptionSetDescription("Processing Groups"),
				progressbar.OptionSetTheme(progressbar.Theme{
					Saucer:        "=",
					SaucerHead:    ">",
					SaucerPadding: " ",
					BarStart:      "[",
					BarEnd:        "]",
				}),
				progressbar.OptionSetWidth(40),
				progressbar.OptionClearOnFinish(),
				progressbar.OptionSetRenderBlankState(true),
				progressbar.OptionEnableColorCodes(true),
				progressbar.OptionShowCount(),
				progressbar.OptionSetPredictTime(false),
				progressbar.OptionFullWidth(),
			)
			
			for _, group := range groups.Items {
				bar.Add(1)
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
			fmt.Println() // New line after progress bar
		}
	}

	// Get Service Accounts
	sas, err := k8sClient.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing service accounts: %v", err)
	}
	
	bar := progressbar.NewOptions(len(sas.Items),
		progressbar.OptionSetDescription("Processing Service Accounts"),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionSetWidth(40),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionSetPredictTime(false),
		progressbar.OptionFullWidth(),
	)
	
	for _, sa := range sas.Items {
		bar.Add(1)
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
	fmt.Println() // New line after progress bar
	
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
			perms, err := getRolePermissions(clientset, rb.RoleRef, rb.Namespace)
			if err != nil {
				log.Printf("Warning: Could not fetch permissions for %s %s: %v", identity.Type, identity.Name, err)
				continue // Continue instead of returning error
			}
			permissions = append(permissions, perms...)
		}
	}
	
	// Process cluster role bindings
	for _, crb := range clusterRoleBindings.Items {
		if isIdentityInBinding(identity, crb.Subjects) {
			perms, err := getRolePermissions(clientset, crb.RoleRef, "")
			if err != nil {
				log.Printf("Warning: Could not fetch permissions for %s %s: %v", identity.Type, identity.Name, err)
				continue // Continue instead of returning error
			}
			permissions = append(permissions, perms...)
		}
	}
	
	return permissions, nil
}

func CheckIdentityPermissions(config *PermissionsConfig, identity Identity) []Violation {
	var violations []Violation
	
	bar := progressbar.NewOptions(len(config.SensitivePermissions),
		progressbar.OptionSetDescription(fmt.Sprintf("Checking %s:%s", identity.Type, identity.Name)),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionSetWidth(40),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionSetPredictTime(false),
		progressbar.OptionFullWidth(),
		progressbar.OptionOnCompletion(func() {
			fmt.Print("\r") // Return carriage to start of line
		}),
		progressbar.OptionUseANSICodes(true), // Use ANSI codes for better terminal control
	)
	
	for _, sensitivePermission := range config.SensitivePermissions {
		bar.Add(1)
		time.Sleep(10 * time.Millisecond) // Small delay to prevent flickering
		
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
	
	fmt.Print("\033[K") // Clear the line
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
	// Maps to store violations by scope and type
	clusterViolations := make(map[string]map[string][]Identity) // violation -> type -> identities
	namespaceViolations := make(map[string]map[string][]Identity) // namespace -> type -> identities

	// Organize violations
	for _, v := range violations {
		if v.Scope == "cluster-wide" {
			if _, exists := clusterViolations[v.Rule]; !exists {
				clusterViolations[v.Rule] = make(map[string][]Identity)
			}
			// Avoid duplicate identities for same violation
			if !containsIdentity(clusterViolations[v.Rule][v.Identity.Type], v.Identity) {
				clusterViolations[v.Rule][v.Identity.Type] = append(clusterViolations[v.Rule][v.Identity.Type], v.Identity)
			}
		} else {
			if _, exists := namespaceViolations[v.Identity.Namespace]; !exists {
				namespaceViolations[v.Identity.Namespace] = make(map[string][]Identity)
			}
			if !containsIdentity(namespaceViolations[v.Identity.Namespace][v.Identity.Type], v.Identity) {
				namespaceViolations[v.Identity.Namespace][v.Identity.Type] = append(namespaceViolations[v.Identity.Namespace][v.Identity.Type], v.Identity)
			}
		}
	}

	// Print report header
	fmt.Println("\n=== Security Policy Violation Report ===")
	fmt.Printf("Generated: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println("=======================================")

	// Print Cluster-Wide Violations
	fmt.Println("\n🌐 Cluster-Wide Access Violations:")
	fmt.Println("================================")
	
	if len(clusterViolations) == 0 {
		fmt.Println("No cluster-wide violations found.")
	} else {
		for violationRule, typeMap := range clusterViolations {
			fmt.Printf("\n⚠️  %s\n", violationRule)
			
			// Print Users
			if users := typeMap["user"]; len(users) > 0 {
				fmt.Println("  👤 Users:")
				for _, identity := range users {
					fmt.Printf("    - %s\n", identity.Name)
				}
			}
			
			// Print Groups
			if groups := typeMap["group"]; len(groups) > 0 {
				fmt.Println("  👥 Groups:")
				for _, identity := range groups {
					fmt.Printf("    - %s\n", identity.Name)
				}
			}
			
			// Print Service Accounts
			if sas := typeMap["serviceAccount"]; len(sas) > 0 {
				fmt.Println("  🔧 Service Accounts:")
				for _, identity := range sas {
					fmt.Printf("    - %s\n", identity.Name)
				}
			}
		}
	}

	// Print Namespace-Scoped Violations
	fmt.Println("\n📁 Namespace-Scoped Violations:")
	fmt.Println("============================")
	
	if len(namespaceViolations) == 0 {
		fmt.Println("No namespace-scoped violations found.")
	} else {
		for namespace, typeMap := range namespaceViolations {
			fmt.Printf("\n📂 Namespace: %s\n", namespace)
			
			// Print Users
			if users := typeMap["user"]; len(users) > 0 {
				fmt.Println("  👤 Users:")
				for _, identity := range users {
					fmt.Printf("    - %s\n", identity.Name)
				}
			}
			
			// Print Groups
			if groups := typeMap["group"]; len(groups) > 0 {
				fmt.Println("  👥 Groups:")
				for _, identity := range groups {
					fmt.Printf("    - %s\n", identity.Name)
				}
			}
			
			// Print Service Accounts
			if sas := typeMap["serviceAccount"]; len(sas) > 0 {
				fmt.Println("  🔧 Service Accounts:")
				for _, identity := range sas {
					fmt.Printf("    - %s\n", identity.Name)
				}
			}
		}
	}

	// Print Summary
	printSummary(clusterViolations, namespaceViolations)
}

// Helper function to check if an identity is already in a slice
func containsIdentity(identities []Identity, identity Identity) bool {
	for _, i := range identities {
		if i.Name == identity.Name && i.Type == identity.Type && i.Namespace == identity.Namespace {
			return true
		}
	}
	return false
}

// Modified summary function
func printSummary(clusterViolations map[string]map[string][]Identity, namespaceViolations map[string]map[string][]Identity) {
	fmt.Println("\n📊 Summary:")
	fmt.Println("=========")
	
	// Count unique violations and identities
	clusterViolationCount := len(clusterViolations)
	namespacesAffected := len(namespaceViolations)
	
	var totalIdentities int
	identityTypes := make(map[string]int)
	
	// Count cluster-wide identities
	for _, typeMap := range clusterViolations {
		for idType, identities := range typeMap {
			identityTypes[idType] += len(identities)
			totalIdentities += len(identities)
		}
	}
	
	// Count namespace-scoped identities
	for _, typeMap := range namespaceViolations {
		for idType, identities := range typeMap {
			identityTypes[idType] += len(identities)
			totalIdentities += len(identities)
		}
	}
	
	fmt.Printf("\nTotal Violations Found:\n")
	fmt.Printf("- Cluster-wide violation types: %d\n", clusterViolationCount)
	fmt.Printf("- Namespaces affected: %d\n", namespacesAffected)
	fmt.Printf("- Total identities affected: %d\n", totalIdentities)
	
	fmt.Printf("\nBreakdown by Identity Type:\n")
	if count := identityTypes["user"]; count > 0 {
		fmt.Printf("- 👤 Users: %d\n", count)
	}
	if count := identityTypes["group"]; count > 0 {
		fmt.Printf("- 👥 Groups: %d\n", count)
	}
	if count := identityTypes["serviceAccount"]; count > 0 {
		fmt.Printf("- 🔧 Service Accounts: %d\n", count)
	}
}

func getRolePermissions(clientset *kubernetes.Clientset, roleRef rbacv1.RoleRef, namespace string) ([]IdentityPermission, error) {
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
		role, err := clientset.RbacV1().Roles(namespace).Get(ctx, roleRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("error getting role %s in namespace %s: %v", roleRef.Name, namespace, err)
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

