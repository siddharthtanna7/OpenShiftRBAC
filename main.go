package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"flag"
	"sync"
	"sort"
	"strings"

	"gopkg.in/yaml.v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	openshiftclientset "github.com/openshift/client-go/user/clientset/versioned"
	"github.com/schollz/progressbar/v3"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
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
	Resources   []string
	Verbs       []string
	APIGroups   []string
	ClusterWide bool    // true if from ClusterRoleBinding
	Namespace   string  // namespace of the RoleBinding if not cluster-wide
}

type Violation struct {
	Identity    Identity
	Rule        string
	Impact      string
	Scope       string
	Namespace   string
}

// Add this struct to consolidate violations
type ConsolidatedViolation struct {
    Identity    string
    Type        string   // "user", "group", or "serviceAccount"
    Namespace   string   // for serviceAccounts
    Violations  []string
    Impacts     map[string]string  // maps violation name to impact
    Scope       string
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
	
	// Create a channel for collecting violations
	violationsChan := make(chan []Violation, len(filteredIdentities))
	var wg sync.WaitGroup
	
	// Create a semaphore to limit concurrent goroutines
	semaphore := make(chan struct{}, 10) // Limit to 10 concurrent checks
	
	total := len(filteredIdentities)
	progress := 0
	mu := sync.Mutex{}
	
	updateProgress := func() {
		mu.Lock()
		progress++
		fmt.Printf("\rAnalyzing permissions: %d/%d (%d%%)", progress, total, (progress*100)/total)
		mu.Unlock()
	}
	
	// Check permissions concurrently
	for _, identity := range filteredIdentities {
		wg.Add(1)
		go func(id Identity) {
			defer wg.Done()
			defer updateProgress()
			semaphore <- struct{}{} // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore
			
			identityViolations := CheckIdentityPermissions(config, id)
			if len(identityViolations) > 0 {
				violationsChan <- identityViolations
			}
		}(identity)
	}
	
	// Close violations channel when all goroutines complete
	go func() {
		wg.Wait()
		close(violationsChan)
	}()
	
	// Collect violations
	var violations []Violation
	for v := range violationsChan {
		violations = append(violations, v...)
	}

	fmt.Println("\n📊 Generating report...")
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
	
	// Get Users and Groups only if we're on OpenShift and they're requested
	if isOpenShift && ocClient != nil && (checkUsers || checkAll) {
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
	}

	if isOpenShift && ocClient != nil && (checkGroups || checkAll) {
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

	// Get Service Accounts only if requested
	if checkServiceAccounts || checkAll {
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
	}
	
	return identities, nil
}

func getIdentityPermissions(clientset *kubernetes.Clientset, identity Identity) ([]IdentityPermission, error) {
	var permissions []IdentityPermission
	ctx := context.Background()
	
	// Get all role bindings and cluster role bindings in one request
	roleBindings, err := clientset.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing role bindings: %v", err)
	}
	
	clusterRoleBindings, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing cluster role bindings: %v", err)
	}
	
	// Create maps to cache roles and cluster roles
	roleCache := make(map[string]*rbacv1.Role)
	clusterRoleCache := make(map[string]*rbacv1.ClusterRole)
	
	// Process role bindings in parallel
	var wg sync.WaitGroup
	permChan := make(chan []IdentityPermission, len(roleBindings.Items)+len(clusterRoleBindings.Items))
	semaphore := make(chan struct{}, 5) // Limit concurrent API requests
	
	// Process role bindings
	for _, rb := range roleBindings.Items {
		if isIdentityInBinding(identity, rb.Subjects) {
			wg.Add(1)
			go func(rb rbacv1.RoleBinding) {
				defer wg.Done()
				semaphore <- struct{}{} // Acquire semaphore
				defer func() { <-semaphore }() // Release semaphore
				
				perms, err := getRolePermissionsWithCache(clientset, rb.RoleRef, rb.Namespace, roleCache, clusterRoleCache)
				if err != nil {
					if !k8serrors.IsNotFound(err) {
						log.Printf("Warning: Error fetching permissions for %s: %v", rb.Name, err)
					}
					return
				}
				if len(perms) > 0 {
					permChan <- perms
				}
			}(rb)
		}
	}
	
	// Process cluster role bindings
	for _, crb := range clusterRoleBindings.Items {
		if isIdentityInBinding(identity, crb.Subjects) {
			wg.Add(1)
			go func(crb rbacv1.ClusterRoleBinding) {
				defer wg.Done()
				semaphore <- struct{}{} // Acquire semaphore
				defer func() { <-semaphore }() // Release semaphore
				
				perms, err := getRolePermissionsWithCache(clientset, crb.RoleRef, "", roleCache, clusterRoleCache)
				if err != nil {
					if !k8serrors.IsNotFound(err) {
						log.Printf("Warning: Error fetching permissions for %s: %v", crb.Name, err)
					}
					return
				}
				if len(perms) > 0 {
					permChan <- perms
				}
			}(crb)
		}
	}
	
	// Close permission channel when all goroutines complete
	go func() {
		wg.Wait()
		close(permChan)
	}()
	
	// Collect permissions
	for perms := range permChan {
		permissions = append(permissions, perms...)
	}
	
	return permissions, nil
}

// Add role caching
func getRolePermissionsWithCache(
	clientset *kubernetes.Clientset,
	roleRef rbacv1.RoleRef,
	namespace string,
	roleCache map[string]*rbacv1.Role,
	clusterRoleCache map[string]*rbacv1.ClusterRole,
) ([]IdentityPermission, error) {
	var permissions []IdentityPermission
	ctx := context.Background()
	
	switch roleRef.Kind {
	case "ClusterRole":
		// Check cache first
		if cachedRole, exists := clusterRoleCache[roleRef.Name]; exists {
			return convertRulesToPermissions(cachedRole.Rules), nil
		}
		
		role, err := clientset.RbacV1().ClusterRoles().Get(ctx, roleRef.Name, metav1.GetOptions{})
		if err != nil {
			if k8serrors.IsNotFound(err) {
				// Skip if role doesn't exist
				return nil, nil
			}
			return nil, err
		}
		
		// Cache the result
		clusterRoleCache[roleRef.Name] = role
		return convertRulesToPermissions(role.Rules), nil
		
	case "Role":
		cacheKey := fmt.Sprintf("%s/%s", namespace, roleRef.Name)
		if cachedRole, exists := roleCache[cacheKey]; exists {
			return convertRulesToPermissions(cachedRole.Rules), nil
		}
		
		role, err := clientset.RbacV1().Roles(namespace).Get(ctx, roleRef.Name, metav1.GetOptions{})
		if err != nil {
			if k8serrors.IsNotFound(err) {
				// Skip if role doesn't exist
				return nil, nil
			}
			return nil, err
		}
		
		// Cache the result
		roleCache[cacheKey] = role
		return convertRulesToPermissions(role.Rules), nil
	}
	
	return permissions, nil
}

// Helper function to convert rules to permissions
func convertRulesToPermissions(rules []rbacv1.PolicyRule) []IdentityPermission {
	var permissions []IdentityPermission
	for _, rule := range rules {
		permissions = append(permissions, IdentityPermission{
			Resources: rule.Resources,
			Verbs:     rule.Verbs,
			APIGroups: rule.APIGroups,
		})
	}
	return permissions
}

func CheckIdentityPermissions(config *PermissionsConfig, identity Identity) []Violation {
	var violations []Violation
	
	for _, sensitivePermission := range config.SensitivePermissions {
		if isIdentityExcepted(identity, sensitivePermission.Exceptions) {
			continue
		}

		for _, perm := range identity.Permissions {
			if hasMatchingPermissions([]IdentityPermission{perm}, sensitivePermission) {
				scope := "cluster-wide"
				if !perm.ClusterWide {
					scope = "namespace"
				}
				
				violations = append(violations, Violation{
					Identity: identity,
					Rule:     sensitivePermission.Name,
					Impact:   sensitivePermission.Impact,
					Scope:    scope,
					Namespace: perm.Namespace,
				})
				break  // Break after first match for this permission
			}
		}
	}
	return violations
}

// Add this function to determine the correct scope
func determineScope(identityPerms []IdentityPermission, sensitivePermission Permission) string {
	// Default to namespace scope
	scope := "namespace"
	
	for _, identityPerm := range identityPerms {
		// Check if this is a cluster-wide permission
		if identityPerm.ClusterWide {
			// If we find any cluster-wide permission that matches, mark it as cluster-wide
			if hasOverlap(identityPerm.Resources, sensitivePermission.Resources) &&
			   hasOverlap(identityPerm.Verbs, sensitivePermission.Verbs) &&
			   hasOverlap(identityPerm.APIGroups, sensitivePermission.APIGroups) {
				scope = "cluster-wide"
				break
			}
		}
	}
	
	return scope
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
	// Single map for all violations
	consolidatedViolations := make(map[string]*ConsolidatedViolation)

	// Consolidate violations
	for _, v := range violations {
		var key string
		if v.Identity.Type == "serviceAccount" {
			key = fmt.Sprintf("%s:%s", v.Identity.Namespace, v.Identity.Name)
		} else {
			key = v.Identity.Name
		}

		if _, exists := consolidatedViolations[key]; !exists {
			consolidatedViolations[key] = &ConsolidatedViolation{
				Identity:   v.Identity.Name,
				Type:      v.Identity.Type,
				Namespace: v.Identity.Namespace,
				Violations: make([]string, 0),
				Impacts:   make(map[string]string),
				Scope:     v.Scope,
			}
		}
		addViolation(consolidatedViolations[key], v)
	}

	// Print Report
	fmt.Println("\nSECURITY VIOLATIONS REPORT")
	fmt.Println("==========================")

	printViolationsByType(consolidatedViolations, "user", "Users")
	printViolationsByType(consolidatedViolations, "group", "Groups")
	printViolationsByType(consolidatedViolations, "serviceAccount", "Service Accounts")

	printSummary(consolidatedViolations)
}

func printViolationsByType(violations map[string]*ConsolidatedViolation, identityType, header string) {
	typeViolations := make([]*ConsolidatedViolation, 0)
	for _, v := range violations {
		if v.Type == identityType {
			typeViolations = append(typeViolations, v)
		}
	}

	// Sort identities for consistent output
	sort.Slice(typeViolations, func(i, j int) bool {
		return typeViolations[i].Identity < typeViolations[j].Identity
	})

	if len(typeViolations) > 0 {
		fmt.Printf("\n%s\n", header)
		fmt.Println(strings.Repeat("-", len(header)))

		for _, v := range typeViolations {
			if len(v.Violations) > 0 {
				fmt.Printf("\n%s: %s\n", identityType, v.Identity)
				
				fmt.Println("Violations:")
				sort.Strings(v.Violations)
				for _, violation := range v.Violations {
					fmt.Printf("  * %s\n", violation)
					fmt.Printf("    Impact: %s\n", v.Impacts[violation])
					if v.Scope == "namespace" {
						fmt.Printf("    Namespace: %s\n", v.Namespace)
					}
				}
			}
		}
	}
}

func addViolation(cv *ConsolidatedViolation, v Violation) {
	if !contains(cv.Violations, v.Rule) {
		cv.Violations = append(cv.Violations, v.Rule)
		cv.Impacts[v.Rule] = v.Impact
		cv.Namespace = v.Identity.Namespace
		cv.Scope = v.Scope
	}
}

// Modified summary function
func printSummary(violations map[string]*ConsolidatedViolation) {
	fmt.Println("\nSUMMARY")
	fmt.Println("-------")
	
	// Count identities by type
	identityTypes := make(map[string]int)
	clusterWideCount := 0
	namespaceCount := 0
	
	// Count violations by scope and identity type
	for _, v := range violations {
		identityTypes[v.Type]++
		if v.Scope == "cluster-wide" {
			clusterWideCount++
		} else {
			namespaceCount++
		}
	}
	
	fmt.Printf("\nTotal Violations Found:\n")
	fmt.Printf("- Cluster-wide violations: %d\n", clusterWideCount)
	fmt.Printf("- Namespace-scoped violations: %d\n", namespaceCount)
	fmt.Printf("- Total identities affected: %d\n", len(violations))
	
	fmt.Printf("\nBreakdown by Identity Type:\n")
	if count := identityTypes["user"]; count > 0 {
		fmt.Printf("- Users: %d\n", count)
	}
	if count := identityTypes["group"]; count > 0 {
		fmt.Printf("- Groups: %d\n", count)
	}
	if count := identityTypes["serviceAccount"]; count > 0 {
		fmt.Printf("- Service Accounts: %d\n", count)
	}
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
	// If no specific type is selected and -all is not set, use the explicitly set flags
	if !checkAll {
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
	return true
}

// Add the missing isIdentityExcepted function
func isIdentityExcepted(identity Identity, exceptions struct {
	Users           []string `yaml:"users"`
	ServiceAccounts []string `yaml:"serviceAccounts"`
	Groups          []string `yaml:"groups"`
}) bool {
	switch identity.Type {
	case "user":
		return contains(exceptions.Users, identity.Name)
	case "serviceAccount":
		// For service accounts, check with namespace prefix
		saName := fmt.Sprintf("%s:%s", identity.Namespace, identity.Name)
		return contains(exceptions.ServiceAccounts, saName)
	case "group":
		return contains(exceptions.Groups, identity.Name)
	default:
		return false
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

