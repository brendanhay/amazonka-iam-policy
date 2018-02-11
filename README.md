# Amazon IAM Policy Documents

* [Description](#description)
* [Example](#example)
* [Contribute](#contribute)
* [Licence](#licence)


## Description

This library provides data types and combinators that allow you to declare,
encode, and decode the [IAM JSON policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies.html)
language with a modicum of safety, minus any extreme type-level features.

The IAM policy documents can be safely constructed via the provided datatypes
and mapped, folded, and traversed via the provided instances, combinators,
and lenses. The resulting structure can then be encoded as a valid IAM JSON
policy document for using with Amazon IAM and related services.

The details of what goes into a policy vary for each service, depending on what
actions the service makes available, what types of resources it contains, and
so on. When you're writing policies for a specific service, it's helpful to see
examples of policies for that service. View the [AWS Services That Work with IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-services-that-work-with-iam.html)
documentation for more information.


## Example

The following example sets up S3 bucket management:

```haskell
{-# LANGUAGE OverloadedLists   #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import qualified Amazonka-Iam-Policy.IAM.Policy as Policy

main :: IO ()
main =
    print . Policy.encode $
        Policy.document
            [ Policy.allow
                { Policy.action   = Policy.some ["s3:*"]
                , Policy.resource =
                    Policy.some
                        [ "arn:aws:s3:::<BUCKET-NAME>"
                        , "arn:aws:s3:::<BUCKET-NAME>/*"
                        ]
                }
            , Policy.deny
                { Policy.action   = Policy.not ["s3:*"]
                , Policy.resource =
                    Policy.not
                        [
                        , "arn:aws:s3:::<BUCKET-NAME>"
                        , "arn:aws:s3:::<BUCKET-NAME>/*"
                        ]
                }
            ]
```

Resulting in the following encoded IAM JSON policy document:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::<BUCKET-NAME>",
        "arn:aws:s3:::<BUCKET-NAME>/*"
      ]
    },
    {
      "Effect": "Deny",
      "NotAction": "s3:*",
      "NotResource": [
        "arn:aws:s3:::<BUCKET-NAME>",
        "arn:aws:s3:::<BUCKET-NAME>/*"
      ]
    }
  ]
}
```


## Contribute

For any problems, comments, or feedback please create an issue [here on GitHub](https://github.com/brendanhay/amazonka-iam-policy/issues).


## Licence

`amazonka-iam-policy` is released under the [Mozilla Public License Version 2.0](http://www.mozilla.org/MPL/).
