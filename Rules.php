<?php
namespace App\PHPStan\Rules;

use PHPStan\Rules\Rule;
use PHPStan\Analyser\Scope;
use PHPStan\Node\Expr\MethodCallNode;
use PHPStan\Node\Expr\FuncCallNode;

class SqlInjectionRule implements Rule
{
    public function getNodeType(): string
    {
        return MethodCallNode::class;  // Check method calls
    }

    public function processNode(Node $node, Scope $scope): array
    {
        if ($node instanceof MethodCallNode) {
            // Check if method is DB::select or any similar raw query
            $methodName = $node->name->toString();
            if (in_array($methodName, ['select', 'insert', 'update', 'delete'])) {
                // Check if user input is being directly passed (indicating potential SQL Injection)
                // Here we could analyze if user input is not properly sanitized
                // For example: DB::select("SELECT * FROM users WHERE name = '" . $userInput . "';");
                return ['Potential SQL Injection detected in query'];
            }
        }

        return [];
    }
}
