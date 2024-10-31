package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"

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
}

// Add this function to detect cluster type
func isOpenShiftCluster(clientset *kubernetes.Clientset) bool {
	_, err := clientset.RESTClient().Get().AbsPath("/apis/user.openshift.io").DoRaw(context.Background())
	return err == nil
}

func main() {
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

	// Check permissions and collect violations
	var violations []Violation
	for _, identity := range identities {
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
	// Group violations by identity type
	userViolations := make(map[string][]Violation)
	saViolations := make(map[string][]Violation)
	groupViolations := make(map[string][]Violation)
	
	for _, v := range violations {
		switch v.Identity.Type {
		case "user":
			userViolations[v.Identity.Name] = append(userViolations[v.Identity.Name], v)
		case "serviceAccount":
			saViolations[v.Identity.Name] = append(saViolations[v.Identity.Name], v)
		case "group":
			groupViolations[v.Identity.Name] = append(groupViolations[v.Identity.Name], v)
		}
	}
	
	// Output formatted results
	fmt.Println("\nUsers")
	fmt.Println("-------")
	outputViolationGroup(userViolations)
	
	fmt.Println("\nServiceAccounts")
	fmt.Println("-------------------")
	outputViolationGroup(saViolations)
	
	fmt.Println("\nGroups")
	fmt.Println("-----------")
	outputViolationGroup(groupViolations)
}

func outputViolationGroup(violations map[string][]Violation) {
	for identity, vs := range violations {
		for _, v := range vs {
			fmt.Printf("- Rule: %q\n", v.Rule)
			fmt.Printf("    a) Identity: %s\n", identity)
			if v.Identity.Namespace != "" {
				fmt.Printf("    b) Scope: Namespace: %s\n", v.Identity.Namespace)
			} else {
				fmt.Printf("    b) Scope: Cluster-wide\n")
			}
			fmt.Println()
		}
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
