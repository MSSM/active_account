ActiveAccount
=============

Provides ActiveRecord like access to ldap directories, including Microsoft's Active Directory.


Examples
========

    user = SomeDirectory.find("dvader")
    user.description = "Something something dark side"
    user.save


    addresses = SomeDirectory.find(:all, :sn => "Smith").map do |account|
      account.mail.first # We use first since net/ldap returns values in an array, even if only one
    end


Requirements
============

- Rails 3
- ruby-net-ldap


Instructions
============

1. Define ldap servers in config/ldap.yml ("example/ldap.yml" shows you how)
2. Create an Account model that either inherits from ActiveAccount::Base, or from ActiveDirectoryAccount.
   Take a look at "example/example_account.rb". The file name must be "app/model/SomethingAccount.rb"
   where the Something should match the directory name in your ldap.yml file.


Issues & Concerns
=================

- Creating users easier will be coming soon, but right now you'll have to somehow manually setup 
  attributes like dn by hand. This currently is just too coupled to our environment to release.
- We don't have any tests for this up on github yet.
- Some of the code was written a couple years ago, and may not be totally up to snuff (but it works!)
- The caching module isn't included at this time, since it's tightly coupled to our environment. This means
  that large result sets won't be returned as fast they could, do to reloading the schema all the time. 
- We didn't include our authentication controller at this time.
- Alot of the code is more rails2-ish than I'd like. We're really impressed with rails3 and can't
  wait to copy it, and to make heavy use of its ActiveModel.
- We should make this a gem.



Copyright (c) 2011 Jeff Beck, released under the MIT license
