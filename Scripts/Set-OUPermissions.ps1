function Set-OUPermissions{
<#
.DESCRIPTION
The function will delegate the permission for a group to join a computer to a domain 

.EXAMPLE
Set-OUPermissions -Group "Delegated Users" -LDAPPath "ou=Mobile,ou=Computers,ou=Test2,ou=!Offices,dc=corpnet,dc=liox,dc=org"
#>
   [CmdletBinding()]
   param(
      [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=0)]
      [ValidateNotNullOrEmpty()]
      [System.String]
      $Group,
      
      [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=1)]
      [ValidateNotNullOrEmpty()]
      [System.String]
      $LDAPPath
   )
   begin {
      try {
         import-module activedirectory
         $guidNull                       = new-object Guid 00000000-0000-0000-0000-000000000000
         $guidComputerObject             = new-object Guid bf967a86-0de6-11d0-a285-00aa003049e2
         $guidUserAccountRestrictions    = new-object Guid 4c164200-20c0-11d0-a768-00aa006e0529
         $guidServicePrincipalName       = new-object Guid f3a64788-5306-11d1-a9c5-0000f80367c1
         $guidDNSHostName                = new-object Guid 72e39547-7b18-11d1-adef-00c04fd8d5cd
         $guidUserForceChangePassword    = new-object Guid 00299570-246d-11d0-a768-00aa006e0529
       
      } 
      catch {
      }
   }
   process {
      try {
         # The First Part of the exercise will be to collect the SID for the Group we will be delegating to
         $groupObject = Get-ADGroup $Group
         $groupSID = new-object System.Security.Principal.SecurityIdentifier $groupObject.SID
         
         #Now we will link to the OU Object
         $ADObject = [ADSI]("LDAP://" + $LDAPPath)
         
         # Next we are going to create an Access Control Entry
 
         # Create/delete Computer Objects
         # PropagationFlags      : None
         # InheritanceFlags      : ContainerInherit
         # ObjectType            : bf967a86-0de6-11d0-a285-00aa003049e2
         # InheritanceType       : All
         # InheritedObjectType   : 00000000-0000-0000-0000-000000000000
         # ObjectFlags           : ObjectAceTypePresent
         # ActiveDirectoryRights : CreateChild, DeleteChild
         # 
         $ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"CreateChild, DeleteChild","Allow",$guidComputerObject,"All",$guidNull
         $ADObject.ObjectSecurity.AddAccessRule($ace)
         
         
         # Read and write Account Restrictions
         # PropagationFlags      : InheritOnly
         # InheritanceFlags      : ContainerInherit
         # ObjectType            : 4c164200-20c0-11d0-a768-00aa006e0529
         # InheritanceType       : Descendents
         # InheritedObjectType   : bf967a86-0de6-11d0-a285-00aa003049e2
         # ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
         # ActiveDirectoryRights : ReadProperty, WriteProperty
 
         $ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"ReadProperty, WriteProperty","Allow",$guidUserAccountRestrictions,"Descendents",$guidComputerObject
         $ADObject.ObjectSecurity.AddAccessRule($ace)
         
         # Validated write and write to service principal name
         # PropagationFlags      : InheritOnly
         # InheritanceFlags      : ContainerInherit
         # ObjectType            : f3a64788-5306-11d1-a9c5-0000f80367c1
         # InheritanceType       : Descendents
         # InheritedObjectType   : bf967a86-0de6-11d0-a285-00aa003049e2
         # ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
         # ActiveDirectoryRights : Self
 
         $ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"Self, WriteProperty","Allow",$guidServicePrincipalName,"Descendents",$guidComputerObject
         $ADObject.ObjectSecurity.AddAccessRule($ace)

         # Validated write and Read and write DNS host name attributes
         # PropagationFlags      : InheritOnly
         # InheritanceFlags      : ContainerInherit
         # ObjectType            : 72e39547-7b18-11d1-adef-00c04fd8d5cd
         # InheritanceType       : Descendents
         # InheritedObjectType   : bf967a86-0de6-11d0-a285-00aa003049e2
         # ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
         # ActiveDirectoryRights : Self
 
         $ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"Self, ReadProperty, WriteProperty","Allow",$guidDNSHostName,"Descendents",$guidComputerObject
         $ADObject.ObjectSecurity.AddAccessRule($ace)

         # Reset Password
         # PropagationFlags      : InheritOnly
         # InheritanceFlags      : ContainerInherit
         # ObjectType            : 00299570-246d-11d0-a768-00aa006e0529
         # InheritanceType       : Descendents
         # InheritedObjectType   : bf967a86-0de6-11d0-a285-00aa003049e2
         # ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
         # ActiveDirectoryRights : ExtendedRight
 
         $ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"ExtendedRight","Allow",$guidUserForceChangePassword,"Descendents",$guidComputerObject
         $ADObject.ObjectSecurity.AddAccessRule($ace)

         # Write all properties
         # PropagationFlags      : InheritOnly
         # InheritanceFlags      : ContainerInherit
         # ObjectType            : 00000000-0000-0000-0000-000000000000
         # InheritanceType       : Descendents
         # InheritedObjectType   : bf967a86-0de6-11d0-a285-00aa003049e2
         # ObjectFlags           : InheritedObjectAceTypePresent
         # ActiveDirectoryRights : WriteProperty
 
         $ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID,"WriteProperty","Allow",$guidNull,"Descendents",$guidComputerObject
         $ADObject.ObjectSecurity.AddAccessRule($ace)
         
         $ADObject.CommitChanges()
 
      }
      catch {
      }
   }
   end {
      try {
      }
      catch {
      }
   }
}
